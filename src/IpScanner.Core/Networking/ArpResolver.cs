using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace IpScanner.Core.Networking;

/// <summary>Resolves a LAN host's MAC address through the Windows ARP API.</summary>
public static class ArpResolver
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint physAddrLen);

    public static Task<string?> TryGetMacAsync(IPAddress address) =>
        // SendARP blocks for seconds on absent hosts; dedicated threads keep the thread pool from starving.
        Task.Factory.StartNew(() => TryGetMac(address), CancellationToken.None,
            TaskCreationOptions.LongRunning, TaskScheduler.Default);

    public static string? TryGetMac(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6) return NeighborTable.TryGetIpv6Mac(address);
        if (address.AddressFamily != AddressFamily.InterNetwork) return null;
        if (!OperatingSystem.IsWindows() || IPAddress.IsLoopback(address)) return null;

        try
        {
            var mac = new byte[6];
            uint length = (uint)mac.Length;
            uint dest = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
            if (SendARP(dest, 0, mac, ref length) != 0 || length != 6) return null;
            return string.Join(':', mac.Select(b => b.ToString("X2")));
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }
}
