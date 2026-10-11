using System.Net;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Discovery;

public enum GuardVerdict { Allowed, NeedsConfirmation, Rejected }

public sealed record GuardResult(GuardVerdict Verdict, string Message);

public sealed class ScanRejectedException(string message) : Exception(message);

/// <summary>Safety checks that keep scans on private, reasonably sized networks.</summary>
public static class ScanGuard
{
    public static GuardResult Check(Subnet subnet, ScanOptions options)
    {
        bool loopbackOk = options.AllowLoopback && IPAddress.IsLoopback(subnet.NetworkAddress);

        if (!subnet.IsPrivateRange && !loopbackOk)
            return new(GuardVerdict.Rejected,
                $"{subnet} is not a private (RFC 1918) network. Only networks you own and control can be scanned.");

        if (subnet.HostCount > options.MaxHosts)
            return new(GuardVerdict.Rejected,
                $"{subnet} has {subnet.HostCount:N0} addresses, which exceeds the limit of {options.MaxHosts:N0}.");

        if (subnet.PrefixLength < 24)
            return new(GuardVerdict.NeedsConfirmation,
                $"{subnet} contains {subnet.HostCount:N0} addresses, which is larger than a typical home or office /24.");

        return new(GuardVerdict.Allowed, string.Empty);
    }

    public static bool IsAllowedHost(IPAddress address, ScanOptions options) =>
        Subnet.IsPrivate(address) ||
        (options.AllowLoopback && IPAddress.IsLoopback(address)) ||
        // IPv6 hosts are only ever taken from the local link's neighbor cache, so they are on-link by construction.
        (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && NeighborTable.IsIpv6Neighbor(address));
}
