using System.Net;
using System.Net.Sockets;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetProc;

/// <summary>
/// Opens an ETW kernel session and feeds TCP/UDP events into the aggregator.
///
/// Uses the NetworkTCPIP kernel keyword, which is what Windows itself uses to account for
/// per-process network usage - the same underlying source that Task Manager's "Network"
/// column and tools like GlassWire rely on. Crucially, these events carry the PID, so we
/// get the attribution that packet capture (SPAN, pcap, netflow) fundamentally cannot give.
/// </summary>
internal sealed class EtwCollector : IDisposable
{
    // A kernel session must use this well-known name; Windows only permits one.
    // Not a const: the library exposes this as a static readonly field, not a literal.
    private static readonly string SessionName = KernelTraceEventParser.KernelSessionName;

    private readonly Options _options;
    private readonly FlowAggregator _aggregator;
    private readonly ProcessResolver _resolver;

    private TraceEventSession? _session;
    private long _eventsSeen;

    public long EventsSeen => Interlocked.Read(ref _eventsSeen);

    public EtwCollector(Options options, FlowAggregator aggregator, ProcessResolver resolver)
    {
        _options = options;
        _aggregator = aggregator;
        _resolver = resolver;
    }

    /// <summary>
    /// Blocks, processing events, until Stop() is called.
    /// </summary>
    public void Run()
    {
        // If a previous run crashed the session can be left behind; clear it first.
        TraceEventSession.GetActiveSession(SessionName)?.Dispose();

        _session = new TraceEventSession(SessionName);
        _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

        var kernel = _session.Source.Kernel;

        kernel.TcpIpSend += OnTcpSend;
        kernel.TcpIpRecv += OnTcpRecv;
        kernel.TcpIpSendIPV6 += OnTcp6Send;
        kernel.TcpIpRecvIPV6 += OnTcp6Recv;

        kernel.UdpIpSend += d => OnUdp(d, sent: true);
        kernel.UdpIpRecv += d => OnUdp(d, sent: false);
        kernel.UdpIpSendIPV6 += d => OnUdp6(d, sent: true);
        kernel.UdpIpRecvIPV6 += d => OnUdp6(d, sent: false);

        // Blocks until the session is disposed.
        _session.Source.Process();
    }

    // TraceEvent uses a distinct payload type for TCP sends (it carries extra timing
    // fields), so send and receive need separate handlers even though we read the same
    // properties from both. UDP does not have this split.
    private void OnTcpSend(TcpIpSendTraceData d)
    {
        Record(d.ProcessID, d.ProcessName, "tcp", d.daddr, d.dport, d.size, sent: true);
    }

    private void OnTcpRecv(TcpIpTraceData d)
    {
        Record(d.ProcessID, d.ProcessName, "tcp", d.daddr, d.dport, d.size, sent: false);
    }

    private void OnTcp6Send(TcpIpV6SendTraceData d)
    {
        Record(d.ProcessID, d.ProcessName, "tcp", d.daddr, d.dport, d.size, sent: true);
    }

    private void OnTcp6Recv(TcpIpV6TraceData d)
    {
        Record(d.ProcessID, d.ProcessName, "tcp", d.daddr, d.dport, d.size, sent: false);
    }

    private void OnUdp(UdpIpTraceData d, bool sent)
    {
        Record(d.ProcessID, d.ProcessName, "udp", d.daddr, d.dport, d.size, sent);
    }

    private void OnUdp6(UpdIpV6TraceData d, bool sent)
    {
        Record(d.ProcessID, d.ProcessName, "udp", d.daddr, d.dport, d.size, sent);
    }

    private void Record(int pid, string? etwName, string proto, IPAddress remote, int remotePort, int size, bool sent)
    {
        Interlocked.Increment(ref _eventsSeen);

        if (size <= 0)
            return;

        if (_options.ExcludeLocal && IsLocal(remote))
            return;

        if (_options.ExcludeLoopback && IPAddress.IsLoopback(remote))
            return;
        
        var info = _resolver.Resolve(pid, etwName);

        var key = new FlowKey(
            Pid: pid,
            Process: info.Name,
            Protocol: proto,
            RemoteIp: remote.ToString(),
            RemotePort: remotePort);

        _aggregator.Record(key, info.Path, size, sent);
    }

    /// <summary>
    /// Loopback, RFC1918, link-local, and CGNAT (which covers Tailscale's 100.64/10 range).
    /// </summary>
    private static bool IsLocal(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip))
            return true;

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;

        var b = ip.GetAddressBytes();
        if (b.Length != 4)
            return false;

        return b[0] switch
        {
            10 => true,                                    // 10.0.0.0/8
            172 when b[1] >= 16 && b[1] <= 31 => true,     // 172.16.0.0/12
            192 when b[1] == 168 => true,                  // 192.168.0.0/16
            169 when b[1] == 254 => true,                  // 169.254.0.0/16 link-local
            100 when b[1] >= 64 && b[1] <= 127 => true,    // 100.64.0.0/10 CGNAT / Tailscale
            0 => true,                                     // 0.0.0.0/8
            _ => false
        };
    }

    public void Stop() => _session?.Dispose();

    public void Dispose() => _session?.Dispose();
}
