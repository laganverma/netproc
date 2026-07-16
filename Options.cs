namespace NetProc;

/// <summary>
/// Command line options for netproc.
/// </summary>
internal sealed class Options
{
    /// <summary>How often (seconds) aggregated counters are flushed to disk.</summary>
    public int IntervalSeconds { get; private set; } = 10;

    /// <summary>Directory that log files are written to.</summary>
    public string LogFolder { get; private set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "netproc");

    /// <summary>Skip loopback and RFC1918/CGNAT destinations.</summary>
    public bool ExcludeLocal { get; private set; }

    /// <summary>Skip loopback destinations only. Keeps LAN and tailnet traffic.</summary>
    public bool ExcludeLoopback { get; private set; }

    /// <summary>Also echo each flushed record to the console.</summary>
    public bool Verbose { get; private set; }

    /// <summary>Delete log files older than this many days. 0 disables cleanup.</summary>
    public int RetentionDays { get; private set; } = 14;

    public static Options? Parse(string[] args)
    {
        var o = new Options();

        foreach (var arg in args)
        {
            if (arg is "/?" or "-h" or "--help")
                return null;

            if (TryValue(arg, "--interval", out var interval))
            {
                if (!int.TryParse(interval, out var seconds) || seconds < 1)
                    throw new ArgumentException($"--interval must be a positive integer, got '{interval}'.");
                o.IntervalSeconds = seconds;
            }
            else if (TryValue(arg, "--logfolder", out var folder))
            {
                if (string.IsNullOrWhiteSpace(folder))
                    throw new ArgumentException("--logfolder requires a path.");
                o.LogFolder = folder.Trim('"');
            }
            else if (TryValue(arg, "--retention-days", out var retention))
            {
                if (!int.TryParse(retention, out var days) || days < 0)
                    throw new ArgumentException($"--retention-days must be >= 0, got '{retention}'.");
                o.RetentionDays = days;
            }
            else if (arg is "--exclude-local")
            {
                o.ExcludeLocal = true;
            }
            else if (arg is "--exclude-loopback")
            {
                o.ExcludeLoopback = true;
            }
            else if (arg is "--verbose" or "-v")
            {
                o.Verbose = true;
            }
            else
            {
                throw new ArgumentException($"Unknown argument '{arg}'. Use --help for usage.");
            }
        }

        return o;
    }

    private static bool TryValue(string arg, string name, out string value)
    {
        if (arg.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))
        {
            value = arg[(name.Length + 1)..];
            return true;
        }

        value = string.Empty;
        return false;
    }

    public static void PrintUsage()
    {
        Console.WriteLine("""
            netproc - per-process network bandwidth monitoring for Windows via ETW

            Usage: netproc [options]      (must be run as Administrator)

              --interval=<seconds>     Flush interval. Default: 10
              --logfolder=<path>       Log destination.
                                       Default: %ProgramData%\netproc
              --exclude-local          Skip loopback / RFC1918 / CGNAT destinations
              --exclude-loopback       Skip loopback only. Keeps LAN and tailnet.
              --retention-days=<n>     Delete logs older than n days. 0 = keep all.
                                       Default: 14
              --verbose, -v            Echo records to the console as they flush
              --help, -h, /?           This message

            Output: one JSON object per line, aggregated per
                    (pid, process, protocol, remote endpoint) per interval.
            """);
    }
}