using System.Net;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Tests;

public class SubnetTests
{
    [Theory]
    [InlineData("192.168.1.0/24", 254, "192.168.1.0", "192.168.1.255")]
    [InlineData("192.168.1.77/24", 254, "192.168.1.0", "192.168.1.255")]
    [InlineData("10.0.0.0/30", 2, "10.0.0.0", "10.0.0.3")]
    [InlineData("10.0.0.4/31", 2, "10.0.0.4", "10.0.0.5")]
    [InlineData("10.0.0.9/32", 1, "10.0.0.9", "10.0.0.9")]
    public void Calculates_network_and_host_count(string cidr, long hosts, string network, string broadcast)
    {
        Assert.True(Subnet.TryParse(cidr, out var s));
        Assert.Equal(hosts, s!.HostCount);
        Assert.Equal(IPAddress.Parse(network), s.NetworkAddress);
        Assert.Equal(IPAddress.Parse(broadcast), s.BroadcastAddress);
        Assert.Equal(hosts, s.EnumerateHosts().LongCount());
    }

    [Fact]
    public void Enumeration_excludes_network_and_broadcast()
    {
        var hosts = new Subnet(IPAddress.Parse("192.168.1.0"), 24).EnumerateHosts().ToList();
        Assert.Equal(IPAddress.Parse("192.168.1.1"), hosts.First());
        Assert.Equal(IPAddress.Parse("192.168.1.254"), hosts.Last());
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.0"), hosts);
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.255"), hosts);
    }

    [Theory]
    [InlineData("255.255.255.0", 24)]
    [InlineData("255.255.254.0", 23)]
    [InlineData("255.255.0.0", 16)]
    public void Converts_mask_to_prefix(string mask, int prefix) =>
        Assert.Equal(prefix, Subnet.PrefixFromMask(IPAddress.Parse(mask)));

    [Fact]
    public void Rejects_non_contiguous_mask() =>
        Assert.Throws<ArgumentException>(() => Subnet.PrefixFromMask(IPAddress.Parse("255.0.255.0")));

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.254", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("172.15.0.1", false)]
    [InlineData("192.168.50.5", true)]
    [InlineData("192.169.0.1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("127.0.0.1", false)]
    public void Detects_private_addresses(string ip, bool expected) =>
        Assert.Equal(expected, Subnet.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("")]
    [InlineData("192.168.1.0")]
    [InlineData("192.168.1.0/33")]
    [InlineData("nope/24")]
    [InlineData("::1/64")]
    public void TryParse_rejects_bad_input(string text) => Assert.False(Subnet.TryParse(text, out _));

    [Fact]
    public void Contains_checks_membership()
    {
        var s = new Subnet(IPAddress.Parse("192.168.1.0"), 24);
        Assert.True(s.Contains(IPAddress.Parse("192.168.1.200")));
        Assert.False(s.Contains(IPAddress.Parse("192.168.2.1")));
    }
}
