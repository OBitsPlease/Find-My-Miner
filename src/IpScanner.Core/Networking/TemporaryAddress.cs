using System.Net;
using System.Net.Sockets;

namespace IpScanner.Core.Networking;

/// <summary>
/// Builds the administrator scripts that add or remove a temporary IPv4 address, so this PC can reach a
/// device on another IPv4 network that shares the same wire. Every value is validated first.
/// </summary>
public static class TemporaryAddress
{
    public const int DefaultPrefix = 24;

    /// <summary>Picks a host address in the device's /24 that is not the device itself or a likely gateway.</summary>
    public static IPAddress? Pick(IPAddress device, IReadOnlyCollection<Subnet> localSubnets, Func<IPAddress, bool>? isTaken = null)
    {
        if (device.AddressFamily != AddressFamily.InterNetwork || !Subnet.IsPrivate(device)) return null;

        var network = Subnet.Containing(device, DefaultPrefix);
        if (localSubnets.Any(s => s.Contains(device))) return null;

        var bytes = device.GetAddressBytes();
        foreach (int last in Enumerable.Range(10, 241).Where(n => n != bytes[3] && n is not (254 or 255)))
        {
            var candidate = Subnet.FromUInt(network.NetworkValue + (uint)last);
            if (isTaken is null || !isTaken(candidate)) return candidate;
        }

        return null;
    }

    public static string BuildAddScript(int interfaceIndex, IPAddress address, int prefixLength, string statusPath)
    {
        Validate(interfaceIndex, address, prefixLength, statusPath);

        return $$"""
            $ErrorActionPreference = 'Stop'
            try {
              New-NetIPAddress -InterfaceIndex {{interfaceIndex}} -IPAddress '{{address}}' -PrefixLength {{prefixLength}} -SkipAsSource $false | Out-Null
              Start-Sleep -Seconds 3
              $state = (Get-NetIPAddress -InterfaceIndex {{interfaceIndex}} -IPAddress '{{address}}').AddressState
              if ($state -ne 'Preferred') {
                Remove-NetIPAddress -InterfaceIndex {{interfaceIndex}} -IPAddress '{{address}}' -Confirm:$false
                throw "Address is not usable (state: $state); another device may already use it."
              }
              Set-Content '{{statusPath}}' 'ok'
            } catch {
              Set-Content '{{statusPath}}' ('error: ' + $_.Exception.Message)
            }
            """;
    }

    public static string BuildRemoveScript(IEnumerable<(int InterfaceIndex, IPAddress Address)> items, string statusPath)
    {
        ScriptSafety.RequireSafePath(statusPath);
        var lines = new List<string>();
        foreach (var (index, address) in items)
        {
            Validate(index, address, DefaultPrefix, statusPath);
            lines.Add($"Get-NetIPAddress -InterfaceIndex {index} -IPAddress '{address}' -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false");
        }

        return $$"""
            $ErrorActionPreference = 'Stop'
            try {
              {{string.Join("\n  ", lines)}}
              Set-Content '{{statusPath}}' 'ok'
            } catch {
              Set-Content '{{statusPath}}' ('error: ' + $_.Exception.Message)
            }
            """;
    }

    private static void Validate(int interfaceIndex, IPAddress address, int prefixLength, string statusPath)
    {
        if (interfaceIndex <= 0) throw new ArgumentOutOfRangeException(nameof(interfaceIndex));
        if (address.AddressFamily != AddressFamily.InterNetwork || !Subnet.IsPrivate(address))
            throw new ArgumentException("Only private IPv4 addresses can be added.", nameof(address));
        if (prefixLength is < 16 or > 30) throw new ArgumentOutOfRangeException(nameof(prefixLength));
        ScriptSafety.RequireSafePath(statusPath);
    }
}
