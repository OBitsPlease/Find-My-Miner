using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace IpScanner.Core.Networking;

/// <summary>An IPv4 CIDR block with host enumeration and private-range checks.</summary>
public sealed class Subnet : IEquatable<Subnet>
{
    public Subnet(IPAddress address, int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 addresses are supported.", nameof(address));
        if (prefixLength is < 0 or > 32)
            throw new ArgumentOutOfRangeException(nameof(prefixLength));

        PrefixLength = prefixLength;
        NetworkValue = ToUInt(address) & MaskFor(prefixLength);
    }

    public int PrefixLength { get; }
    public uint NetworkValue { get; }
    public uint BroadcastValue => NetworkValue | ~MaskFor(PrefixLength);
    public IPAddress NetworkAddress => FromUInt(NetworkValue);
    public IPAddress BroadcastAddress => FromUInt(BroadcastValue);

    /// <summary>Number of scannable hosts (network and broadcast excluded for /30 and larger).</summary>
    public long HostCount => PrefixLength switch
    {
        32 => 1,
        31 => 2,
        _ => (1L << (32 - PrefixLength)) - 2,
    };

    public bool IsPrivateRange => IsPrivate(NetworkAddress) && IsPrivate(BroadcastAddress);

    public IEnumerable<IPAddress> EnumerateHosts()
    {
        long first = PrefixLength >= 31 ? NetworkValue : (long)NetworkValue + 1;
        long last = PrefixLength >= 31 ? BroadcastValue : (long)BroadcastValue - 1;
        for (long value = first; value <= last; value++)
            yield return FromUInt((uint)value);
    }

    public bool Contains(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork &&
        (ToUInt(address) & MaskFor(PrefixLength)) == NetworkValue;

    /// <summary>Returns the subnet of the given prefix that contains <paramref name="address"/>.</summary>
    public static Subnet Containing(IPAddress address, int prefixLength) => new(address, prefixLength);

    public static Subnet FromMask(IPAddress address, IPAddress mask) => new(address, PrefixFromMask(mask));

    public static int PrefixFromMask(IPAddress mask)
    {
        uint value = ToUInt(mask);
        int prefix = System.Numerics.BitOperations.PopCount(value);
        if (value != MaskFor(prefix))
            throw new ArgumentException("Subnet mask is not contiguous.", nameof(mask));
        return prefix;
    }

    public static bool TryParse(string? text, out Subnet? subnet)
    {
        subnet = null;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var parts = text.Trim().Split('/');
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out int prefix) || prefix is < 0 or > 32)
            return false;

        subnet = new Subnet(address, prefix);
        return true;
    }

    public static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = address.GetAddressBytes();
        return b[0] == 10 ||
               (b[0] == 172 && b[1] is >= 16 and <= 31) ||
               (b[0] == 192 && b[1] == 168);
    }

    public static uint ToUInt(IPAddress address) =>
        BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());

    public static IPAddress FromUInt(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

    private static uint MaskFor(int prefix) => prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);

    public override string ToString() => $"{NetworkAddress}/{PrefixLength}";
    public bool Equals(Subnet? other) => other is not null && other.NetworkValue == NetworkValue && other.PrefixLength == PrefixLength;
    public override bool Equals(object? obj) => Equals(obj as Subnet);
    public override int GetHashCode() => HashCode.Combine(NetworkValue, PrefixLength);
}
