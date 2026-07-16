using System.Collections.Concurrent;
using System.Diagnostics;

namespace NetProc;

/// <summary>
/// Resolves a PID to a process name and image path.
///
/// This exists because of a race that matters in practice: ETW hands us a PID for a
/// packet, but by the time we look it up the process may already have exited (think
/// short-lived installers, update checkers, DNS helpers). So we cache aggressively on
/// first sight and keep serving the cached answer afterwards.
///
/// The cache is keyed by PID alone, which means PID reuse can theoretically mis-attribute
/// traffic to a stale name. Windows does not reuse PIDs quickly, and ETW gives us the
/// process name directly on most events (see EtwCollector), so this is a fallback path
/// rather than the primary source of truth.
/// </summary>
internal sealed class ProcessResolver
{
    private readonly ConcurrentDictionary<int, ProcessInfo> _cache = new();

    public ProcessInfo Resolve(int pid, string? etwSuppliedName)
    {
        // ETW usually gives us the name for free. Trust it, but still cache so we can
        // answer later if a subsequent event arrives without one.
        if (!string.IsNullOrEmpty(etwSuppliedName) && etwSuppliedName != "Unknown")
        {
            return _cache.AddOrUpdate(
                pid,
                _ => Lookup(pid, etwSuppliedName),
                (_, existing) => existing.Path is null ? Lookup(pid, etwSuppliedName) : existing);
        }

        return _cache.GetOrAdd(pid, static p => Lookup(p, null));
    }

    private static ProcessInfo Lookup(int pid, string? fallbackName)
    {
        // PID 0 and 4 are the kernel; they legitimately generate traffic but have no image.
        if (pid == 0)
            return new ProcessInfo("Idle", null);
        if (pid == 4)
            return new ProcessInfo("System", null);

        try
        {
            using var proc = Process.GetProcessById(pid);
            string name = proc.ProcessName;
            string? path = null;

            try
            {
                // MainModule throws for protected / 32-vs-64-bit / already-exiting processes.
                // The name alone is still useful, so treat the path as best-effort.
                path = proc.MainModule?.FileName;
            }
            catch
            {
                // ignored - path stays null
            }

            // Normalise: ETW reports "chrome", we want "chrome.exe" to match Sysmon's Image field.
            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                name += ".exe";

            return new ProcessInfo(name, path);
        }
        catch (ArgumentException)
        {
            // Process already exited between the packet and our lookup.
            return new ProcessInfo(Normalise(fallbackName) ?? $"pid-{pid}", null);
        }
        catch (InvalidOperationException)
        {
            return new ProcessInfo(Normalise(fallbackName) ?? $"pid-{pid}", null);
        }
        catch (Exception)
        {
            // Access denied on protected processes etc.
            return new ProcessInfo(Normalise(fallbackName) ?? $"pid-{pid}", null);
        }
    }

    private static string? Normalise(string? name)
    {
        if (string.IsNullOrEmpty(name))
            return null;

        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe";
    }

    /// <summary>
    /// Drop cache entries for processes that no longer exist, so a long-running session
    /// does not accumulate a stale entry for every short-lived process ever seen.
    /// </summary>
    public void Prune()
    {
        if (_cache.Count < 512)
            return;

        var live = new HashSet<int>();
        foreach (var p in Process.GetProcesses())
        {
            live.Add(p.Id);
            p.Dispose();
        }

        foreach (var pid in _cache.Keys)
        {
            if (!live.Contains(pid) && pid is not (0 or 4))
                _cache.TryRemove(pid, out _);
        }
    }
}

internal readonly record struct ProcessInfo(string Name, string? Path);
