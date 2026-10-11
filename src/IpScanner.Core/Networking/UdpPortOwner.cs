using System.Diagnostics;
using System.Runtime.InteropServices;

namespace IpScanner.Core.Networking;

/// <summary>Finds which local process is listening on a UDP port, to explain bind failures.</summary>
public static class UdpPortOwner
{
    private const int UdpTableOwnerPid = 1;
    private const int AfInet = 2;
    private const int AfInet6 = 23;

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, int reserved);

    public static (int Pid, string? Name)? TryGetOwner(int port)
    {
        if (!OperatingSystem.IsWindows()) return null;

        foreach (var (family, rowSize, portOffset, pidOffset) in new[] { (AfInet, 12, 4, 8), (AfInet6, 28, 20, 24) })
        {
            int? pid = FindPid(family, rowSize, portOffset, pidOffset, port);
            if (pid is null) continue;

            string? name = null;
            try { name = Process.GetProcessById(pid.Value).ProcessName; }
            catch (ArgumentException) { }
            return (pid.Value, name);
        }

        return null;
    }

    private static int? FindPid(int family, int rowSize, int portOffset, int pidOffset, int port)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, UdpTableOwnerPid, 0);
        if (size <= 0) return null;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerPid, 0) != 0) return null;

            int count = Marshal.ReadInt32(buffer);
            for (int i = 0; i < count; i++)
            {
                IntPtr row = buffer + 4 + i * rowSize;
                int rawPort = Marshal.ReadInt32(row + portOffset);
                int rowPort = ((rawPort & 0xff) << 8) | ((rawPort >> 8) & 0xff);
                if (rowPort == port) return Marshal.ReadInt32(row + pidOffset);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return null;
    }
}
