using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace IpScanner.Core.Networking;

public sealed record NetworkAdapterInfo(
    string Id,
    string Name,
    string Description,
    IPAddress LocalAddress,
    IPAddress Mask,
    IPAddress? Gateway,
    Subnet Subnet,
    bool IsVirtual,
    int InterfaceIndex = 0)
{
    public string DisplayName =>
        $"{Name} — {LocalAddress} ({Subnet}){(IsVirtual ? " [virtual]" : string.Empty)}";
}

public static class AdapterDiscovery
{
    private static readonly string[] VirtualMarkers =
    [
        "vethernet", "hyper-v", "virtualbox", "vmware", "docker", "wsl", "loopback",
        "tap-", "tap windows", "wintun", "wireguard", "tailscale", "zerotier",
        "vpn", "openvpn", "nordlynx", "pseudo", "virtual", "bluetooth",
    ];

    public static bool LooksVirtual(string name, string description)
    {
        string text = $"{name} {description}";
        return VirtualMarkers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Active adapters carrying a private IPv4 address; the best candidates come first.</summary>
    public static IReadOnlyList<NetworkAdapterInfo> GetAdapters()
    {
        var result = new List<NetworkAdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                continue;

            var props = nic.GetIPProperties();
            int interfaceIndex = 0;
            try { interfaceIndex = props.GetIPv6Properties().Index; }
            catch (NetworkInformationException) { }

            var gateway = props.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));

            foreach (var unicast in props.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork ||
                    !Subnet.IsPrivate(unicast.Address) ||
                    unicast.IPv4Mask is null)
                    continue;

                Subnet subnet;
                try { subnet = Subnet.FromMask(unicast.Address, unicast.IPv4Mask); }
                catch (ArgumentException) { continue; }

                result.Add(new NetworkAdapterInfo(
                    nic.Id, nic.Name, nic.Description, unicast.Address, unicast.IPv4Mask,
                    gateway, subnet, LooksVirtual(nic.Name, nic.Description), interfaceIndex));
            }
        }

        return Rank(result);
    }

    public static IReadOnlyList<NetworkAdapterInfo> Rank(IEnumerable<NetworkAdapterInfo> adapters) =>
        adapters
            .OrderBy(a => a.IsVirtual)
            .ThenBy(a => a.Gateway is null)
            // The adapter's main network (the one holding its gateway) outranks temporary extra addresses.
            .ThenBy(a => a.Gateway is not null && !a.Subnet.Contains(a.Gateway))
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>Every IPv4 network this PC is on, including virtual and non-private ones.</summary>
    public static IReadOnlyList<Subnet> GetLocalSubnets()
    {
        var result = new List<Subnet>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork || unicast.IPv4Mask is null) continue;
                try { result.Add(Subnet.FromMask(unicast.Address, unicast.IPv4Mask)); }
                catch (ArgumentException) { }
            }
        }

        return result;
    }

    /// <summary>The physical, gateway-attached adapter to scan by default; virtual adapters are never auto-selected.</summary>
    public static NetworkAdapterInfo? Recommend(IEnumerable<NetworkAdapterInfo> adapters) =>
        Rank(adapters).FirstOrDefault(a => !a.IsVirtual);
}
