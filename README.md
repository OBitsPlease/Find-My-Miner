# Find My Miner

A cross-platform Avalonia desktop app that scans **your own local network** for mining rigs and opens each rig's login page in your system browser.

Current version: **0.0.1**

Detects (heuristically, with an explanation for every result):

- **Jasminer** and **VolcMiner** ASICs
- **HiveOS** rigs (CPU/GPU)
- **Miner Dash** dashboards
- Any other device that answers a cgminer-style miner API (shown as *Generic miner*)
- Your own rigs, through custom detection rules

> **Authorized use only.** Scan only networks you own or are permitted to test. The app refuses public address ranges, never guesses passwords, never changes miner settings, and sends no telemetry.

## Run it

- Run **Find My Miner** and press **Scan network**.
- Build from source (needs the .NET 10 SDK):

```powershell
dotnet build IpScanner.sln
dotnet test tests\IpScanner.Core.Tests
dotnet run --project src\IpScanner.App
```

The UI runs on Windows, macOS, and Linux. Login pages open in the operating system's default browser; Find My Miner does not embed a browser or store browser passwords, cookies, or page content.

## Installers

GitHub Actions builds native installers for each supported desktop platform:

- Windows x64: Inno Setup `.exe`
- macOS Apple silicon: `.dmg`
- Linux x64: Debian `.deb`

Download them from the **Build installers** workflow artifacts. The current unsigned `0.0.1` packages may show the operating system's normal warning for software from an unidentified developer. Windows and macOS packages use the BitsPleaseYT installer artwork supplied with the project.

## How scanning works

1. **Subnet.** The physical adapter with a gateway and a private (RFC 1918) IPv4 address is selected automatically, and its real subnet mask is used. VPN, Hyper-V, Docker, VMware, WSL and similar adapters are listed but never auto-selected.
2. **Safety limits.** Public ranges are refused. Networks larger than a `/24` ask for confirmation; more than 1,024 addresses is refused (you can scan the `/24` around your PC instead).
3. **Discovery.** Each address gets a short ping, an ARP lookup *and* TCP connects to a small port set: `22, 80, 443, 1337, 4028, 4200, 8080, 8443, 8888`. ARP answers even when a device blocks ping and has no open probe ports, so any live device on the subnet is listed with its MAC. A second phase finds **IPv6-only** devices on the same link (multicast echo plus the IPv6 neighbor cache) and lists them with an "IPv6 only" status; their IPv4 web page cannot be opened until they get an IPv4 address (restart the device, check your router's DHCP leases, or set a static IPv4). Concurrency and timeouts are bounded and adjustable in Settings.
4. **Identification (read-only).** For responsive hosts the scanner does one anonymous `GET /` per web port (title, headers, first 16 KB, certificate trust), one read-only `version` query on the miner API port 4028, reverse DNS and an ARP lookup for the MAC. No credentials are ever sent.
5. **Scoring.** Fingerprint rules add up to a score: **Confirmed** (80+), **Likely** (50+), **Possible** (15+), otherwise **Unknown**. The detail panel lists the exact reasons, so a false positive is easy to spot. The login URL is built from the device's IP and the port whose page matched; redirects to other hosts are ignored.

Why a device may show as *Unknown*: the rig is asleep, firewalled, runs unfamiliar firmware, or exposes no web page. Add a **custom rule** (Settings) such as a page-title pattern, hostname pattern or port, and rescan.

## Logging in

- **Open** and **Browser** open the detected login URL in your default browser, where your normal password manager and certificate handling apply.
- Self-signed HTTPS certificates are common on miners. Any certificate warning is shown and controlled by your browser.
- App preferences contain no passwords, cookies, or page content. Existing settings remain in the platform's local application-data `IpScanner` folder so upgrades retain prior device history and preferences.

## Listen for IP report

Many miners broadcast their address on UDP port 14235 when their IP/IP-report button is pressed. **Listen for IP report** opens a passive listener (it sends nothing): press Start, then press the button on the miner. Each packet is shown with its source IP (the miner's own address), any IP/MAC in the message, and the raw text, with buttons to open the login page or scan. The port is editable, because the exact protocol varies by vendor and has not been verified for every model. If another program already uses the port (the app names it), stop that program or check whether it already shows the report. A miner with no IPv4 address cannot send a report.

## Other networks (miners that cannot get an address on your LAN)

A miner can end up on a different IPv4 network on the same cable, for example `192.168.50.x` when a second router or DHCP server answers it first. A normal scan cannot reach it, and your router shows it with no IP. **Other networks…** finds such devices:

1. **Start 60-second capture** records only *broadcast* frames (Windows Packet Monitor, `pktmon`) and lists senders whose IPv4 address is outside every network this PC is on, plus devices that are still asking DHCP for an address and not getting one (shown as "no address yet"; these cannot be reached until they get one). Miners can take a minute or two to boot, so wait before capturing. You can press the miner's IP button or restart it during the capture. Nothing is transmitted. This needs administrator permission (a normal Windows prompt) for the capture only.
2. **Reach this device** adds a temporary address in that network (for example `192.168.50.10/24`) to the chosen adapter, then scans that network and lists the miner like any other. It verifies the address is usable (no duplicate) before keeping it.
3. **Remove temporary addresses** undoes it. The app remembers what it added, and offers to remove it when you close the app.

Safety: only private IPv4 addresses are ever added; values placed into administrator scripts are validated; scripts are passed as an encoded command (not a file), so nothing can be swapped after you approve. The capture stops any Packet Monitor session you already had running. Hints such as "Jasminer-style" come from observed broadcast ports and are not proof of the device type.

To permanently fix such a miner, open its web page (via the temporary address) and set a static address on your normal network, outside your router's DHCP pool.

## Naming devices and remembered identification

Select a device and press **F2** (or right-click → **Name & type…**, or use the button in the details panel) to give it your own **name** and, if the scanner got it wrong, a **type** (pick one or type your own, such as "VolcMiner D1"). Names and types are saved by MAC address, so they survive IP changes. A type you set always wins over detection.

The app also remembers each device's strongest solid identification (Likely or better). If a later scan finds only weaker evidence, for example because a miner is still booting, the row shows the remembered type marked **Remembered** instead of downgrading to "Generic miner" or "Unknown". Embedded miners sometimes drop part of a burst of connection attempts, so a host that answers ARP or ping but shows no web port gets a slower second try with fewer simultaneous connections.

## Other features

Light/dark theme, search and filters, *Miners only*, remembered device names and ignore flags (by MAC, so they survive DHCP changes), *New* and *IP changed* markers, rescan of one device or only uncertain/offline ones, copy IP/URL, copy all miner URLs, CSV/JSON export (spreadsheet-formula safe).

## Layout

```
src/IpScanner.Core   scanning, detection, settings, export (no UI)
src/IpScanner.App    cross-platform Avalonia app (MVVM)
tests/               unit + loopback integration tests
```

## Known limitations

- The **Other networks** packet-capture and temporary-address recovery workflow depends on Windows Packet Monitor, PowerShell, and UAC. The rest of the app is cross-platform; this recovery workflow reports that it requires Windows when used on macOS or Linux.
- Web login links need IPv4 (IPv6-only devices are listed but have no link). Fingerprints for Jasminer, VolcMiner, HiveOS and Miner Dash are heuristic and firmware-dependent; the built-in rules are meant to be extended with custom rules.
- Reverse DNS and MAC lookup depend on your router and only work on the local subnet.
- Windows firewalls on a rig can hide its ports from the scan.
