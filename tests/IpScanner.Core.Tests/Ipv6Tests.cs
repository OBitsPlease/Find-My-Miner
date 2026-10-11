using System.Net;
using IpScanner.Core.Detection;
using IpScanner.Core.Discovery;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Tests;

public class Ipv6DiscoveryTests
{
    private static Neighbor N(string ip, string mac, NeighborState state = NeighborState.Stale) =>
        new(IPAddress.Parse(ip), mac, 12, state);

    [Fact]
    public void Picks_one_address_per_mac_preferring_stable_eui64()
    {
        var picked = Ipv6Discovery.PreferOnePerMac(
        [
            N("2600:1700:44a1:e000:9d35:f15e:46ff:6191", "DE:E5:38:F4:64:87", NeighborState.Reachable),
            N("2600:1700:44a1:e000:dce5:38ff:fef4:6487", "DE:E5:38:F4:64:87"),
            N("fe80::dce5:38ff:fef4:6487", "DE:E5:38:F4:64:87", NeighborState.Reachable),
            N("2600:1700:44a1:e000::1", "60:D8:A4:D5:BA:18", NeighborState.Reachable),
        ]);

        Assert.Equal(2, picked.Count);
        Assert.Equal("2600:1700:44a1:e000:dce5:38ff:fef4:6487", picked.Single(p => p.Mac == "DE:E5:38:F4:64:87").Address.ToString());
    }

    [Fact]
    public void Prefers_global_over_link_local_when_neither_is_eui64()
    {
        var picked = Ipv6Discovery.PreferOnePerMac(
        [
            N("fe80::1234:5678:9abc:def0", "AA:AA:AA:AA:AA:AA", NeighborState.Reachable),
            N("2600:1700:44a1:e000:1234:5678:9abc:def0", "AA:AA:AA:AA:AA:AA"),
        ]);

        Assert.False(picked.Single().Address.IsIPv6LinkLocal);
    }

    [Fact]
    public void Reading_the_neighbor_table_never_throws_and_returns_well_formed_entries()
    {
        foreach (var n in NeighborTable.GetIpv6(interfaceIndex: 12))
        {
            Assert.Matches("^([0-9A-F]{2}:){5}[0-9A-F]{2}$", n.Mac);
            Assert.NotEqual(0xff, n.Address.GetAddressBytes()[0]);
        }
    }

    [Fact]
    public void Ipv6_urls_are_bracketed() =>
        Assert.Equal("http://[2600:1700:44a1:e000::46]:8080/",
            UrlSelector.Build("http", IPAddress.Parse("2600:1700:44a1:e000::46"), 8080));

    [Fact]
    public void Public_ipv6_addresses_are_not_scannable_unless_on_link() =>
        Assert.False(ScanGuard.IsAllowedHost(IPAddress.Parse("2001:4860:4860::8888"), new ScanOptions()));

    [Fact]
    public void Link_local_ipv6_hosts_get_no_login_url()
    {
        var http = new HttpEvidence(80, "http", 200, "x", null, null, null, null, true, string.Empty);
        var evidence = new ProbeEvidence(new IPAddress(IPAddress.Parse("fe80::1").GetAddressBytes(), 12), null, null,
            [80], [http], null, null, DateTimeOffset.Now);
        Assert.Null(UrlSelector.Choose(evidence));
    }

    [Fact]
    public void Jasminer_hostname_alone_is_a_likely_match()
    {
        var evidence = new ProbeEvidence(
            IPAddress.Parse("2600:1700:44a1:e000:dce5:38ff:fef4:6487"), "JasMiner.attlocal.net", "DE:E5:38:F4:64:87",
            [22], [], null, TimeSpan.FromMilliseconds(2), DateTimeOffset.Now);

        var result = new MinerDetector().Detect(evidence);
        Assert.Equal(BuiltInFingerprints.Jasminer, result.Platform);
        Assert.Equal(Confidence.Likely, result.Confidence);
        Assert.Null(UrlSelector.Choose(evidence));
    }
}
