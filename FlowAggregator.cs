using System.Collections.Concurrent;

namespace NetProc;

/// <summary>
/// Identity of a flow for aggregation purposes: one process talking to one remote endpoint
/// over one protocol. Deliberately does NOT include the local port - otherwise every new
/// ephemeral source port would create a separate row and a browser would emit hundreds of
/// near-identical records per interval.
/// </summary>
internal readonly record struct FlowKey(
    int Pid,
    string Process,
    string Protocol,
    string RemoteIp,
    int RemotePort);

/// <summary>
/// Mutable byte counters for a flow. Held in a class (not a struct) so we can update it
/// in place inside the concurrent dictionary without replacing the entry.
/// </summary>
internal sealed class FlowCounters
{
    private long _bytesSent;
    private long _bytesRecv;
    private long _packetsSent;
    private long _packetsRecv;

    public string? ProcessPath { get; set; }

    public void AddSent(int bytes)
    {
        Interlocked.Add(ref _bytesSent, bytes);
        Interlocked.Increment(ref _packetsSent);
    }

    public void AddRecv(int bytes)
    {
        Interlocked.Add(ref _bytesRecv, bytes);
        Interlocked.Increment(ref _packetsRecv);
    }

    public (long BytesSent, long BytesRecv, long PacketsSent, long PacketsRecv) Read() =>
        (Interlocked.Read(ref _bytesSent),
         Interlocked.Read(ref _bytesRecv),
         Interlocked.Read(ref _packetsSent),
         Interlocked.Read(ref _packetsRecv));
}

/// <summary>
/// Accumulates per-flow byte counts between flushes.
///
/// ETW fires an event per packet. On a busy machine that is thousands of events per second,
/// which is far too much to write out directly. Aggregating in memory and flushing on an
/// interval collapses that into a handful of lines while preserving the totals.
/// </summary>
internal sealed class FlowAggregator
{
    private ConcurrentDictionary<FlowKey, FlowCounters> _current = new();

    public void Record(FlowKey key, string? processPath, int bytes, bool sent)
    {
        var counters = _current.GetOrAdd(key, _ => new FlowCounters { ProcessPath = processPath });

        // First writer usually wins; fill the path in later if we learn it.
        if (counters.ProcessPath is null && processPath is not null)
            counters.ProcessPath = processPath;

        if (sent)
            counters.AddSent(bytes);
        else
            counters.AddRecv(bytes);
    }

    /// <summary>
    /// Atomically swap out the accumulated data and return it. Events arriving during the
    /// swap land in the new dictionary, so nothing is lost and nothing is double counted.
    /// </summary>
    public IReadOnlyDictionary<FlowKey, FlowCounters> Drain()
    {
        return Interlocked.Exchange(ref _current, new ConcurrentDictionary<FlowKey, FlowCounters>());
    }
}
