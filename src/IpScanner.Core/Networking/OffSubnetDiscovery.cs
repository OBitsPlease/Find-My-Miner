using System.Net;
using System.Text.RegularExpressions;

namespace IpScanner.Core.Networking;

/// <summary>A device whose broadcasts reveal an IPv4 address outside every network this PC belongs to.</summary>
public sealed record OffSubnetDevice(string Mac, IPAddress Address, string Evidence, int? UdpPort, string? Hint)
{
    public string Key => $"{Mac}|{Address}";

    /// <summary>True for a device that is asking DHCP for an address and has none yet.</summary>
    public bool IsAddressless => Address.Equals(IPAddress.Any);

    public string AddressText => IsAddressless ? "(no address yet)" : Address.ToString();
}

/// <summary>
/// Finds devices that sit on the same wire but a different IPv4 network (for example a miner that fell
/// back to 192.168.50.x because DHCP failed). It parses a Windows packet-monitor (pktmon) text capture
/// of broadcast frames; nothing is transmitted.
/// </summary>
public static partial class OffSubnetDiscovery
{
    public const string CaptureFileName = "capture.txt";
    public const string StatusFileName = "status.txt";

    /// <summary>Written by the elevated script as soon as it runs, so the UI knows permission was granted.</summary>
    public const string StartedFileName = "started.txt";
    public const int MinSeconds = 5;
    public const int MaxSeconds = 120;
    public const int DefaultSeconds = 60;

    private static readonly Dictionary<int, string> PortHints = new()
    {
        [1534] = "Jasminer-style IP broadcast (seen from a Jasminer)",
        [14235] = "Bitmain-style IP report (used by many ASIC miners)",
    };

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    [GeneratedRegex(
        @"^\s*(?<mac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}) > [0-9A-Fa-f-]+, ethertype IPv4 \(0x0800\), length \d+: " +
        @"(?<src>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?<sport>\d+))? > (?<dst>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?<dport>\d+))?: (?<proto>[A-Za-z0-9]+)",
        RegexOptions.None, matchTimeoutMilliseconds: 250)]
    private static partial Regex Ipv4FrameRegex();

    [GeneratedRegex(
        @"^\s*(?<mac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}) > [0-9A-Fa-f-]+, ethertype ARP \(0x0806\).*?\btell (?<sender>\d{1,3}(?:\.\d{1,3}){3})",
        RegexOptions.None, matchTimeoutMilliseconds: 250)]
    private static partial Regex ArpFrameRegex();

    /// <summary>
    /// Extracts senders outside every network this PC is on, plus devices that are still asking DHCP for an
    /// address (source 0.0.0.0), unless the same MAC was also seen using a local address.
    /// </summary>
    public static IReadOnlyList<OffSubnetDevice> Parse(IEnumerable<string> lines, IReadOnlyCollection<Subnet> localSubnets)
    {
        var found = new Dictionary<string, OffSubnetDevice>();
        var macsWithLocalAddress = new HashSet<string>();

        foreach (var line in lines)
        {
            if (line.Length > 600) continue;

            try
            {
                var ip = Ipv4FrameRegex().Match(line);
                if (ip.Success)
                {
                    string mac = ip.Groups["mac"].Value.Replace('-', ':').ToUpperInvariant();
                    string proto = ip.Groups["proto"].Value;
                    int? sport = ip.Groups["sport"].Success && int.TryParse(ip.Groups["sport"].Value, out int sp) ? sp : null;
                    int? dport = ip.Groups["dport"].Success && int.TryParse(ip.Groups["dport"].Value, out int dp) ? dp : null;

                    if (ip.Groups["src"].Value == "0.0.0.0" && proto == "UDP" && sport == 68 && dport == 67)
                    {
                        AddAddressless(found, mac);
                        continue;
                    }

                    if (IPAddress.TryParse(ip.Groups["src"].Value, out var srcAddress) && localSubnets.Any(s => s.Contains(srcAddress)))
                        macsWithLocalAddress.Add(mac);

                    string evidence = dport is { } p && proto is "UDP" or "TCP"
                        ? $"{proto} broadcast to port {p}"
                        : $"{proto} broadcast";
                    Add(found, ip.Groups["mac"].Value, ip.Groups["src"].Value, evidence, proto == "UDP" ? dport : null, localSubnets);
                    continue;
                }

                var arp = ArpFrameRegex().Match(line);
                if (arp.Success)
                {
                    if (IPAddress.TryParse(arp.Groups["sender"].Value, out var sender) && localSubnets.Any(s => s.Contains(sender)))
                        macsWithLocalAddress.Add(arp.Groups["mac"].Value.Replace('-', ':').ToUpperInvariant());

                    Add(found, arp.Groups["mac"].Value, arp.Groups["sender"].Value, "ARP request", null, localSubnets);
                }
            }
            catch (RegexMatchTimeoutException)
            {
            }
        }

        return found.Values
            .Where(d => !d.IsAddressless || !macsWithLocalAddress.Contains(d.Mac))
            .OrderBy(d => Subnet.ToUInt(d.Address)).ThenBy(d => d.Mac, StringComparer.Ordinal)
            .ToList();
    }

    private static void AddAddressless(Dictionary<string, OffSubnetDevice> found, string mac)
    {
        var device = new OffSubnetDevice(mac, IPAddress.Any, "Asking for an address (DHCP request)", null,
            "Has no address yet; its DHCP request is not being answered");
        found.TryAdd(device.Key, device);
    }

    private static void Add(
        Dictionary<string, OffSubnetDevice> found, string rawMac, string rawIp, string evidence, int? udpPort,
        IReadOnlyCollection<Subnet> localSubnets)
    {
        if (!IPAddress.TryParse(rawIp, out var address) || !IsCandidate(address) ||
            localSubnets.Any(s => s.Contains(address)))
            return;

        string mac = rawMac.Replace('-', ':').ToUpperInvariant();
        var device = new OffSubnetDevice(mac, address, evidence, udpPort,
            udpPort is { } port && PortHints.TryGetValue(port, out var hint) ? hint : null);

        // Prefer richer evidence (a UDP broadcast with a port) over a bare ARP request.
        if (!found.TryGetValue(device.Key, out var existing) || (existing.UdpPort is null && device.UdpPort is not null))
            found[device.Key] = device;
    }

    private static bool IsCandidate(IPAddress address)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        var b = address.GetAddressBytes();
        bool linkLocal = b[0] == 169 && b[1] == 254;
        return Subnet.IsPrivate(address) || linkLocal;
    }

    /// <summary>Script run with administrator rights: capture only broadcast frames, then convert to text.</summary>
    public static string BuildCaptureScript(string directory, int seconds)
    {
        ScriptSafety.RequireSafePath(directory);
        seconds = Math.Clamp(seconds, MinSeconds, MaxSeconds);

        return $$"""
            $dir = '{{directory}}'
            Set-Content "$dir\{{StartedFileName}}" 'started'
            try {
              pktmon stop 2>&1 | Out-Null
              pktmon filter remove 2>&1 | Out-Null
              pktmon filter add bcast -m FF-FF-FF-FF-FF-FF 2>&1 | Out-Null
              pktmon start --capture --comp nics --pkt-size 128 -f "$dir\capture.etl" 2>&1 | Out-Null
              if (-not (Test-Path "$dir\capture.etl")) { throw 'The capture could not be started (is Packet Monitor available?).' }
              Start-Sleep -Seconds {{seconds}}
              pktmon stop 2>&1 | Out-Null
              pktmon etl2txt "$dir\capture.etl" -o "$dir\{{CaptureFileName}}" 2>&1 | Out-Null
              if (-not (Test-Path "$dir\{{CaptureFileName}}")) { throw 'No capture output was produced.' }
              Set-Content "$dir\{{StatusFileName}}" 'ok'
            } catch {
              Set-Content "$dir\{{StatusFileName}}" ('error: ' + $_.Exception.Message)
            } finally {
              pktmon stop 2>&1 | Out-Null
              pktmon filter remove 2>&1 | Out-Null
            }
            """;
    }
}

/// <summary>Guards values that are placed into scripts that run with administrator rights.</summary>
public static partial class ScriptSafety
{
    [GeneratedRegex(@"^[A-Za-z]:\\[A-Za-z0-9 _.\-\\]+$", RegexOptions.None, matchTimeoutMilliseconds: 250)]
    private static partial Regex SafePathRegex();

    public static void RequireSafePath(string path)
    {
        if (!SafePathRegex().IsMatch(path) || path.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException("Path contains characters that are not allowed in an elevated script.", nameof(path));
    }
}
