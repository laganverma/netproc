using System.Diagnostics;
using System.Security.Principal;

namespace NetProc;

internal static class Program
{
    private static int Main(string[] args)
    {
        Options options;
        try
        {
            var parsed = Options.Parse(args);
            if (parsed is null)
            {
                Options.PrintUsage();
                return 0;
            }
            options = parsed;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 2;
        }

        if (!IsElevated())
        {
            Console.Error.WriteLine("""
                error: netproc must be run as Administrator.

                ETW kernel providers are privileged. Right-click your terminal and choose
                "Run as administrator", then try again.
                """);
            return 1;
        }

        var aggregator = new FlowAggregator();
        var resolver = new ProcessResolver();
        using var log = new JsonLogWriter(options.LogFolder, options.RetentionDays);
        using var collector = new EtwCollector(options, aggregator, resolver);

        Console.WriteLine($"netproc - writing to {options.LogFolder}");
        Console.WriteLine($"  interval      : {options.IntervalSeconds}s");
        Console.WriteLine($"  exclude local : {options.ExcludeLocal}");
        Console.WriteLine($"  excl loopback : {options.ExcludeLoopback}");
        Console.WriteLine($"  retention     : {(options.RetentionDays == 0 ? "unlimited" : options.RetentionDays + " days")}");
        Console.WriteLine("Press Ctrl+C to stop.");
        Console.WriteLine();

        using var shutdown = new CancellationTokenSource();

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;          // don't let the CLR kill us mid-flush
            Console.WriteLine("\nstopping...");
            shutdown.Cancel();
            collector.Stop();
        };

        // The ETW session blocks its thread, so it runs on its own.
        var etwThread = new Thread(() =>
        {
            try
            {
                collector.Run();
            }
            catch (Exception ex) when (!shutdown.IsCancellationRequested)
            {
                Console.Error.WriteLine($"fatal: ETW session failed: {ex.Message}");
                shutdown.Cancel();
            }
        })
        {
            IsBackground = true,
            Name = "netproc-etw"
        };
        etwThread.Start();

        var flushTimer = Stopwatch.StartNew();
        long totalRecords = 0;

        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                Thread.Sleep(250);

                if (flushTimer.Elapsed.TotalSeconds < options.IntervalSeconds)
                    continue;

                flushTimer.Restart();
                totalRecords += Flush(log, aggregator, options);
                resolver.Prune();
            }
        }
        finally
        {
            // Capture whatever accumulated since the last flush.
            totalRecords += Flush(log, aggregator, options);
            log.Flush();
        }

        Console.WriteLine($"stopped. {collector.EventsSeen:N0} ETW events -> {totalRecords:N0} records.");
        return 0;
    }

    private static int Flush(JsonLogWriter log, FlowAggregator aggregator, Options options)
    {
        var batch = aggregator.Drain();
        if (batch.Count == 0)
            return 0;

        var now = DateTime.UtcNow;

        foreach (var (key, counters) in batch)
        {
            log.Write(now, key, counters);

            if (options.Verbose)
            {
                var (sent, recv, _, _) = counters.Read();
                Console.WriteLine(
                    $"{key.Process,-28} {key.Protocol} {key.RemoteIp}:{key.RemotePort,-6} " +
                    $"up {Human(sent),9}  down {Human(recv),9}");
            }
        }

        log.Flush();
        return batch.Count;
    }

    private static string Human(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB"
    };

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
