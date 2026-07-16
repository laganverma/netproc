using System.Text;
using System.Text.Json;

namespace NetProc;

/// <summary>
/// Writes one JSON object per line to a daily-rotated file.
///
/// JSON Lines is used rather than CSV because Splunk (and ELK) parse it natively with no
/// field extraction config, and because it tolerates fields being absent - the process path
/// is genuinely unavailable for some processes and an empty CSV column is ambiguous.
/// </summary>
internal sealed class JsonLogWriter : IDisposable
{
    private readonly string _folder;
    private readonly int _retentionDays;
    private readonly string _hostname;

    private StreamWriter? _writer;
    private DateOnly _openDate;

    private static readonly JsonWriterOptions JsonOpts = new() { Indented = false };

    public JsonLogWriter(string folder, int retentionDays)
    {
        _folder = folder;
        _retentionDays = retentionDays;
        _hostname = Environment.MachineName;

        Directory.CreateDirectory(_folder);
    }

    public string CurrentFile => Path.Combine(_folder, $"netproc-{_openDate:yyyyMMdd}.log");

    private StreamWriter GetWriter()
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);

        if (_writer is not null && _openDate == today)
            return _writer;

        // Date rolled over (or first use): close yesterday, open today.
        _writer?.Flush();
        _writer?.Dispose();

        _openDate = today;
        var path = Path.Combine(_folder, $"netproc-{today:yyyyMMdd}.log");

        // Append, not truncate: restarting netproc must not destroy the day's data.
        _writer = new StreamWriter(
            new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        CleanupOldLogs();
        return _writer;
    }

    public void Write(DateTime timestampUtc, FlowKey key, FlowCounters counters)
    {
        var (bytesSent, bytesRecv, packetsSent, packetsRecv) = counters.Read();

        var buffer = new MemoryStream(256);
        using (var json = new Utf8JsonWriter(buffer, JsonOpts))
        {
            json.WriteStartObject();
            json.WriteString("ts", timestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            json.WriteString("machine_name", _hostname);
            json.WriteNumber("pid", key.Pid);
            json.WriteString("process", key.Process);

            if (counters.ProcessPath is not null)
                json.WriteString("path", counters.ProcessPath);

            json.WriteString("proto", key.Protocol);
            json.WriteString("remote_ip", key.RemoteIp);
            json.WriteNumber("remote_port", key.RemotePort);
            json.WriteNumber("bytes_sent", bytesSent);
            json.WriteNumber("bytes_recv", bytesRecv);
            json.WriteNumber("bytes_total", bytesSent + bytesRecv);
            json.WriteNumber("packets_sent", packetsSent);
            json.WriteNumber("packets_recv", packetsRecv);
            json.WriteEndObject();
        }

        var writer = GetWriter();
        writer.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
    }

    public void Flush() => _writer?.Flush();

    private void CleanupOldLogs()
    {
        if (_retentionDays <= 0)
            return;

        try
        {
            var cutoff = DateTime.UtcNow.AddDays(-_retentionDays);
            foreach (var file in Directory.EnumerateFiles(_folder, "netproc-*.log"))
            {
                if (File.GetLastWriteTimeUtc(file) < cutoff)
                    File.Delete(file);
            }
        }
        catch (Exception ex)
        {
            // Never let log housekeeping take the collector down.
            Console.Error.WriteLine($"[warn] log cleanup failed: {ex.Message}");
        }
    }

    public void Dispose()
    {
        _writer?.Flush();
        _writer?.Dispose();
    }
}
