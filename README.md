# netproc

Per-process network bandwidth monitoring for Windows via ETW, with JSON output for Splunk / ELK. A GlassWire alternative you can pipe into your own stack.

`netproc` answers the question packet capture cannot: **which application used the bandwidth**. It reads Windows kernel network events (the same source Task Manager uses), aggregates bytes per process per remote endpoint, and writes JSON Lines to disk.

```json
{"ts":"2026-07-15T12:00:10Z","host":"LAGAN-DELL-WIN","pid":1234,"process":"chrome.exe","path":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","proto":"tcp","remote_ip":"142.250.183.14","remote_port":443,"bytes_sent":45231,"bytes_recv":892341,"bytes_total":937572,"packets_sent":89,"packets_recv":641}
```

## Why

Network sensors (SPAN mirrors, NetFlow, ntopng, Wireshark) see packets. Packets do not carry process names, so no amount of wire-level capture will tell you that `chrome.exe` used 2 GB while `spotify.exe` used 400 MB. That information only exists inside the OS.

Sysmon Event ID 3 gets you *connections* with process names, but no byte counts. `netproc` fills the gap: bytes **and** process, in a format you can ship anywhere.

## Requirements

- Windows 10 / 11
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) to build
- **Administrator** to run (ETW kernel providers are privileged)

## Build

```powershell
git clone https://github.com/<you>/netproc.git
cd netproc
dotnet build -c Release
```

Single-file executable:

```powershell
dotnet publish -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true
```

## Run

From an **elevated** terminal:

```powershell
.\netproc.exe
```

| Option | Default | Description |
| --- | --- | --- |
| `--interval=<seconds>` | `10` | Flush interval |
| `--logfolder=<path>` | `%ProgramData%\netproc` | Log destination |
| `--exclude-local` | off | Skip loopback / RFC1918 / CGNAT (incl. Tailscale `100.64/10`) |
| `--exclude-loopback` | off | Skip loopback only. Keeps LAN and tailnet traffic. |
| `--retention-days=<n>` | `14` | Delete older logs. `0` keeps everything |
| `--verbose`, `-v` | off | Echo records to the console |
| `--help`, `-h`, `/?` | | Usage |

Watch it live:

```powershell
.\netproc.exe --verbose --interval=5
```

## Output

One JSON object per line, aggregated per `(pid, process, protocol, remote_ip, remote_port)` per interval. Files rotate daily: `netproc-YYYYMMDD.log`.

| Field | Description |
| --- | --- |
| `ts` | Flush timestamp, UTC, ISO 8601 |
| `host` | Machine name |
| `pid` | Process ID |
| `process` | Image name, e.g. `chrome.exe` |
| `path` | Full image path (omitted when unavailable) |
| `proto` | `tcp` or `udp` |
| `remote_ip` | Destination address |
| `remote_port` | Destination port |
| `bytes_sent` / `bytes_recv` / `bytes_total` | Bytes in the interval |
| `packets_sent` / `packets_recv` | Packet counts in the interval |

The local port is deliberately excluded from the aggregation key. Including it would emit a separate record for every ephemeral source port, turning one browser into hundreds of near-identical rows per interval.

## Shipping to Splunk

Point a Universal Forwarder at the log folder. In `inputs.conf`:

```ini
[monitor://C:\ProgramData\netproc\netproc-*.log]
sourcetype = netproc
index = windows
```

And in `props.conf`:

```ini
[netproc]
INDEXED_EXTRACTIONS = json
KV_MODE = none
TIME_PREFIX = "ts":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
SHOULD_LINEMERGE = false
```

Then, bandwidth by application:

```
index=windows sourcetype=netproc
| stats sum(bytes_total) as bytes by process
| eval MB=round(bytes/1024/1024,2)
| sort - MB
```

Where an application is sending data, on a map:

```
index=windows sourcetype=netproc
| iplocation remote_ip
| search Country=*
| geostats sum(bytes_total) by process
```

Pairs naturally with Sysmon Event ID 3, which shares the `process` + `remote_ip` + `remote_port` keys — join them for connections *and* volume in one view.

## How it works

```
Microsoft-Windows-Kernel-Network (ETW)
  -> TcpIpSend / TcpIpRecv / UdpIpSend / UdpIpRecv  (each carries a PID)
  -> resolve PID to image name (cached; survives process exit)
  -> aggregate in memory, keyed by process + remote endpoint
  -> flush JSON Lines every N seconds
  -> daily-rotated log file
```

ETW fires an event per packet, which is far too much to write directly — a busy machine produces thousands per second. Aggregating in memory and flushing on an interval collapses that into a handful of lines per flush while preserving exact totals.

## Known limitations

- **Process exit races.** A process can die between the packet and the name lookup. `netproc` caches names on first sight and falls back to the name ETW supplies, but very short-lived processes may appear as `pid-1234`.
- **PID reuse.** Cached names are keyed by PID. Windows does not recycle PIDs quickly, and ETW supplies the name on most events, so mis-attribution is unlikely but not impossible.
- **VPN and tunnel interfaces.** If traffic exits via a VPN or a Tailscale exit node, `remote_ip` is still the true destination as seen by the local stack — but be aware `--exclude-local` filters the `100.64/10` CGNAT range that Tailscale uses.
- **One kernel session.** Windows permits a single kernel ETW session. If another tool holds it, `netproc` will take it over.
- **Not a service (yet).** Runs as a console app; use Task Scheduler ("Run with highest privileges", "At startup") to run it unattended.

## License

MIT. See [LICENSE](LICENSE).
