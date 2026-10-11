using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace IpScanner.Core.Networking;

public enum NeighborState { Unreachable = 0, Incomplete = 1, Probe = 2, Delay = 3, Stale = 4, Reachable = 5, Permanent = 6 }

public sealed record Neighbor(IPAddress Address, string Mac, int InterfaceIndex, NeighborState State);

/// <summary>Reads the OS neighbor (ARP / NDP) cache through the Windows IP Helper API.</summary>
public static class NeighborTable
{
    private const int RowSize = 88;
    private const int RowsOffset = 8;

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void FreeMibTable(IntPtr table);

    /// <summary>Resolved IPv6 neighbors on one interface; multicast, incomplete and unreachable entries are dropped.</summary>
    public static IReadOnlyList<Neighbor> GetIpv6(int interfaceIndex) =>
        Read().Where(n => n.InterfaceIndex == interfaceIndex).ToList();

    public static bool IsIpv6Neighbor(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 &&
        Read().Any(n => n.Address.Equals(address) || n.Address.GetAddressBytes().AsSpan().SequenceEqual(address.GetAddressBytes()));

    public static string? TryGetIpv6Mac(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return Read().FirstOrDefault(n => n.Address.GetAddressBytes().AsSpan().SequenceEqual(bytes))?.Mac;
    }

    private static List<Neighbor> Read()
    {
        var result = new List<Neighbor>();
        if (!OperatingSystem.IsWindows()) return result;

        IntPtr table;
        try
        {
            if (GetIpNetTable2(23, out table) != 0) return result;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return result;
        }

        try
        {
            int count = Marshal.ReadInt32(table);
            for (int i = 0; i < count; i++)
            {
                IntPtr row = table + RowsOffset + i * RowSize;
                if ((ushort)Marshal.ReadInt16(row) != 23) continue;

                var addressBytes = new byte[16];
                Marshal.Copy(row + 8, addressBytes, 0, 16);
                int interfaceIndex = Marshal.ReadInt32(row + 28);
                int macLength = Marshal.ReadInt32(row + 72);
                var state = (NeighborState)Marshal.ReadInt32(row + 76);

                if (macLength != 6 || state is NeighborState.Unreachable or NeighborState.Incomplete or NeighborState.Permanent)
                    continue;
                if (addressBytes[0] == 0xff) continue;

                var macBytes = new byte[6];
                Marshal.Copy(row + 40, macBytes, 0, 6);
                if (macBytes.All(b => b == 0)) continue;

                var address = new IPAddress(addressBytes);
                if (address.IsIPv6LinkLocal) address = new IPAddress(addressBytes, interfaceIndex);

                result.Add(new Neighbor(address, string.Join(':', macBytes.Select(b => b.ToString("X2"))), interfaceIndex, state));
            }
        }
        finally
        {
            FreeMibTable(table);
        }

        return result;
    }
}
