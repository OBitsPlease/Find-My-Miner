using System.Net;
using IpScanner.Core.Networking;
using IpScanner.Core.Settings;

namespace IpScanner.Core.Tests;

public class OffSubnetTests
{
    private static readonly Subnet Home = new(IPAddress.Parse("192.168.1.0"), 24);

    // Captured from a real Jasminer on this network (pktmon text format).
    private const string RealJasminerFrame =
        "\tDE-E5-38-F4-64-87 > FF-FF-FF-FF-FF-FF, ethertype IPv4 (0x0800), length 282: 192.168.50.253.1534 > 192.168.50.255.1534: UDP, length 240";

    [Fact]
    public void Parses_the_real_jasminer_broadcast()
    {
        var device = Assert.Single(OffSubnetDiscovery.Parse([RealJasminerFrame], [Home]));
        Assert.Equal("DE:E5:38:F4:64:87", device.Mac);
        Assert.Equal(IPAddress.Parse("192.168.50.253"), device.Address);
        Assert.Equal(1534, device.UdpPort);
        Assert.Contains("UDP broadcast to port 1534", device.Evidence);
        Assert.NotNull(device.Hint);
    }

    [Fact]
    public void Ignores_senders_on_networks_this_pc_belongs_to()
    {
        var line = "\tAA-AA-AA-AA-AA-AA > FF-FF-FF-FF-FF-FF, ethertype IPv4 (0x0800), length 60: 192.168.1.40.5353 > 224.0.0.251.5353: UDP, length 20";
        Assert.Empty(OffSubnetDiscovery.Parse([line], [Home]));

        // Once the PC has an address on that network, the device is reachable and no longer "off-subnet".
        Assert.Empty(OffSubnetDiscovery.Parse([RealJasminerFrame], [Home, new Subnet(IPAddress.Parse("192.168.50.10"), 24)]));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("100.64.1.5")]
    public void Ignores_public_senders(string src)
    {
        var line = $"\tAA-AA-AA-AA-AA-AA > FF-FF-FF-FF-FF-FF, ethertype IPv4 (0x0800), length 60: {src}.68 > 255.255.255.255.67: UDP, length 20";
        Assert.Empty(OffSubnetDiscovery.Parse([line], [Home]));
    }

    [Fact]
    public void Reads_arp_requests_and_prefers_udp_evidence_for_the_same_device()
    {
        var arp = "\tDE-E5-38-F4-64-87 > FF-FF-FF-FF-FF-FF, ethertype ARP (0x0806), Request who-has 192.168.50.1 tell 192.168.50.253, length 28";
        var onlyArp = Assert.Single(OffSubnetDiscovery.Parse([arp], [Home]));
        Assert.Equal("ARP request", onlyArp.Evidence);

        var both = Assert.Single(OffSubnetDiscovery.Parse([arp, RealJasminerFrame, arp], [Home]));
        Assert.Equal(1534, both.UdpPort);
    }

    [Fact]
    public void Reports_link_local_169_254_devices()
    {
        var line = "\tBB-BB-BB-BB-BB-BB > FF-FF-FF-FF-FF-FF, ethertype IPv4 (0x0800), length 60: 169.254.7.7.14235 > 169.254.255.255.14235: UDP, length 30";
        var device = Assert.Single(OffSubnetDiscovery.Parse([line], [Home]));
        Assert.Equal(14235, device.UdpPort);
    }

    [Fact]
    public void Reports_devices_still_asking_dhcp_for_an_address()
    {
        var discover = "\t34-13-43-E3-30-BE > FF-FF-FF-FF-FF-FF, ethertype IPv4 (0x0800), length 342: 0.0.0.0.68 > 255.255.255.255.67: UDP, length 300";
        var device = Assert.Single(OffSubnetDiscovery.Parse([discover, discover], [Home]));
        Assert.True(device.IsAddressless);
        Assert.Equal("(no address yet)", device.AddressText);
        Assert.Equal("34:13:43:E3:30:BE", device.Mac);
    }

    [Fact]
    public void Dhcp_requesters_that_also_use_a_local_address_are_not_reported()
    {
        var discover = "\tA0-B7-65-2A-83-A8 > FF-FF-FF-FF-FF-FF, ethertype IPv4 (0x0800), length 342: 0.0.0.0.68 > 255.255.255.255.67: UDP, length 300";
        var arp = "\tA0-B7-65-2A-83-A8 > FF-FF-FF-FF-FF-FF, ethertype ARP (0x0806), Request who-has 192.168.1.1 tell 192.168.1.111, length 28";
        Assert.Empty(OffSubnetDiscovery.Parse([discover, arp], [Home]));
    }

    [Fact]
    public void Garbage_and_oversized_lines_are_ignored() =>
        Assert.Empty(OffSubnetDiscovery.Parse(["", "not a frame", new string('A', 5000), "\tZZ > FF, ethertype IPv4"], [Home]));

    [Fact]
    public void Capture_script_has_expected_commands_and_clamps_duration()
    {
        string script = OffSubnetDiscovery.BuildCaptureScript(@"C:\Users\me\AppData\Local\IpScanner\capture\abc", 9999);
        Assert.Contains("pktmon filter add bcast -m FF-FF-FF-FF-FF-FF", script);
        Assert.Contains("Start-Sleep -Seconds 120", script);
        Assert.Contains(@"C:\Users\me\AppData\Local\IpScanner\capture\abc", script);
        Assert.Contains(OffSubnetDiscovery.StartedFileName, script);
    }

    [Theory]
    [InlineData(@"C:\x'; Remove-Item C:\ -Recurse; '")]
    [InlineData(@"C:\a$b")]
    [InlineData(@"C:\a\..\b")]
    [InlineData(@"relative\path")]
    [InlineData("C:\\a`b")]
    public void Unsafe_paths_are_rejected_before_reaching_an_elevated_script(string path) =>
        Assert.Throws<ArgumentException>(() => OffSubnetDiscovery.BuildCaptureScript(path, 10));
}

public class TemporaryAddressTests
{
    private const string Status = @"C:\Users\me\AppData\Local\IpScanner\capture\s.txt";
    private static readonly Subnet Home = new(IPAddress.Parse("192.168.1.0"), 24);

    [Fact]
    public void Picks_dot_10_in_the_devices_network_and_never_the_device_itself()
    {
        Assert.Equal(IPAddress.Parse("192.168.50.10"), TemporaryAddress.Pick(IPAddress.Parse("192.168.50.253"), [Home]));
        Assert.Equal(IPAddress.Parse("192.168.50.11"), TemporaryAddress.Pick(IPAddress.Parse("192.168.50.10"), [Home]));
    }

    [Fact]
    public void Skips_taken_addresses_and_refuses_networks_already_local_or_public()
    {
        var picked = TemporaryAddress.Pick(IPAddress.Parse("192.168.50.253"), [Home], ip => ip.ToString() is "192.168.50.10" or "192.168.50.11");
        Assert.Equal(IPAddress.Parse("192.168.50.12"), picked);

        Assert.Null(TemporaryAddress.Pick(IPAddress.Parse("192.168.1.77"), [Home]));
        Assert.Null(TemporaryAddress.Pick(IPAddress.Parse("8.8.8.8"), [Home]));
    }

    [Fact]
    public void Add_script_is_built_from_validated_values_and_checks_for_duplicates()
    {
        string script = TemporaryAddress.BuildAddScript(12, IPAddress.Parse("192.168.50.10"), 24, Status);
        Assert.Contains("New-NetIPAddress -InterfaceIndex 12 -IPAddress '192.168.50.10' -PrefixLength 24 -SkipAsSource $false", script);
        Assert.Contains("AddressState", script);
    }

    [Theory]
    [InlineData(0, "192.168.50.10", 24)]
    [InlineData(12, "8.8.8.8", 24)]
    [InlineData(12, "192.168.50.10", 8)]
    [InlineData(12, "192.168.50.10", 31)]
    [InlineData(12, "fe80::1", 24)]
    public void Add_script_rejects_unsafe_input(int index, string ip, int prefix) =>
        Assert.ThrowsAny<ArgumentException>(() => TemporaryAddress.BuildAddScript(index, IPAddress.Parse(ip), prefix, Status));

    [Fact]
    public void Remove_script_covers_every_item_and_tolerates_missing_addresses()
    {
        string script = TemporaryAddress.BuildRemoveScript(
            [(12, IPAddress.Parse("192.168.50.10")), (7, IPAddress.Parse("10.9.8.10"))], Status);
        Assert.Contains("-InterfaceIndex 12 -IPAddress '192.168.50.10'", script);
        Assert.Contains("-InterfaceIndex 7 -IPAddress '10.9.8.10'", script);
        Assert.Contains("SilentlyContinue", script);
    }

    [Fact]
    public void Adapter_ranking_keeps_the_main_network_ahead_of_a_temporary_address()
    {
        var gateway = IPAddress.Parse("192.168.1.254");
        NetworkAdapterInfo A(string ip, string cidrNet, int prefix) => new("id", "Ethernet", "Intel", IPAddress.Parse(ip),
            IPAddress.Parse("255.255.255.0"), gateway, new Subnet(IPAddress.Parse(cidrNet), prefix), false, 12);

        var ranked = AdapterDiscovery.Rank([A("192.168.50.10", "192.168.50.0", 24), A("192.168.1.79", "192.168.1.0", 24)]);
        Assert.Equal("192.168.1.79", ranked[0].LocalAddress.ToString());
    }

    [Fact]
    public void Temporary_addresses_survive_a_settings_round_trip()
    {
        var s = new AppSettings();
        s.TemporaryAddresses.Add(new TemporaryAddressRecord { InterfaceIndex = 12, Address = "192.168.50.10", ForDevice = "JasMiner" });
        var copy = SettingsStore.Clone(s);
        var target = new AppSettings();
        target.CopyFrom(copy);
        Assert.Equal("192.168.50.10", Assert.Single(target.TemporaryAddresses).Address);
    }
}
