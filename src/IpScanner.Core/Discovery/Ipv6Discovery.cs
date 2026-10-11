using System.Net;
using System.Net.NetworkInformation;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Discovery;

/// <summary>Finds devices on the local link that only have IPv6, using multicast echo plus the neighbor cache.</summary>
public static class Ipv6Discovery
{
    private static readonly byte[] AllNodes = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    /// <summary>Returns at most one preferred IPv6 address per MAC on the adapter's link.</summary>
    public static async Task<IReadOnlyList<Neighbor>> DiscoverAsync(NetworkAdapterInfo adapter, CancellationToken ct)
    {
        if (adapter.InterfaceIndex <= 0) return [];

        // Link-local all-nodes echo makes hosts that answer it show up in the neighbor cache.
        var target = new IPAddress(AllNodes, adapter.InterfaceIndex);
        for (int attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                using var ping = new Ping();
                await ping.SendPingAsync(target, TimeSpan.FromMilliseconds(1200)).WaitAsync(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is PingException or InvalidOperationException or System.Net.Sockets.SocketException)
            {
                break;
            }
        }

        await Task.Delay(300, ct);
        return PreferOnePerMac(NeighborTable.GetIpv6(adapter.InterfaceIndex));
    }

    /// <summary>Prefers stable EUI-64 addresses, then global over link-local, then freshly reachable entries.</summary>
    public static IReadOnlyList<Neighbor> PreferOnePerMac(IEnumerable<Neighbor> neighbors) =>
        neighbors
            .GroupBy(n => n.Mac)
            .Select(g => g
                .OrderByDescending(IsEui64)
                .ThenBy(n => n.Address.IsIPv6LinkLocal)
                .ThenByDescending(n => n.State == NeighborState.Reachable)
                .First())
            .OrderBy(n => n.Mac, StringComparer.Ordinal)
            .ToList();

    private static bool IsEui64(Neighbor n)
    {
        var b = n.Address.GetAddressBytes();
        return b[11] == 0xff && b[12] == 0xfe;
    }
}
