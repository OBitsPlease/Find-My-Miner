using System.Net;
using IpScanner.Core.Discovery;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Tests;

public class ScanGuardTests
{
    private static readonly ScanOptions Options = new();

    [Fact]
    public void Allows_private_slash24() =>
        Assert.Equal(GuardVerdict.Allowed, ScanGuard.Check(new Subnet(IPAddress.Parse("192.168.1.0"), 24), Options).Verdict);

    [Fact]
    public void Requires_confirmation_for_larger_than_slash24() =>
        Assert.Equal(GuardVerdict.NeedsConfirmation, ScanGuard.Check(new Subnet(IPAddress.Parse("10.0.0.0"), 23), Options).Verdict);

    [Fact]
    public void Rejects_networks_above_the_hard_cap() =>
        Assert.Equal(GuardVerdict.Rejected, ScanGuard.Check(new Subnet(IPAddress.Parse("10.0.0.0"), 16), Options).Verdict);

    [Theory]
    [InlineData("8.8.8.0", 24)]
    [InlineData("172.32.0.0", 24)]
    [InlineData("169.254.0.0", 24)]
    [InlineData("127.0.0.0", 24)]
    public void Rejects_public_ranges(string ip, int prefix) =>
        Assert.Equal(GuardVerdict.Rejected, ScanGuard.Check(new Subnet(IPAddress.Parse(ip), prefix), Options).Verdict);

    [Fact]
    public void Loopback_requires_explicit_opt_in()
    {
        var loopback = new Subnet(IPAddress.Loopback, 32);
        Assert.Equal(GuardVerdict.Rejected, ScanGuard.Check(loopback, Options).Verdict);
        Assert.Equal(GuardVerdict.Allowed, ScanGuard.Check(loopback, Options with { AllowLoopback = true }).Verdict);
    }

    [Fact]
    public void Normalizes_options_to_safe_bounds()
    {
        var o = new ScanOptions { MaxConcurrentHosts = 100_000, ConnectTimeout = TimeSpan.Zero }.Normalized();
        Assert.Equal(ScanOptions.MaxConcurrency, o.MaxConcurrentHosts);
        Assert.True(o.ConnectTimeout >= TimeSpan.FromMilliseconds(100));
    }
}

public class AdapterDiscoveryTests
{
    private static NetworkAdapterInfo Adapter(string name, string desc, bool virt, bool gateway) =>
        new(name, name, desc, IPAddress.Parse("192.168.1.10"), IPAddress.Parse("255.255.255.0"),
            gateway ? IPAddress.Parse("192.168.1.1") : null,
            new Subnet(IPAddress.Parse("192.168.1.0"), 24), virt);

    [Theory]
    [InlineData("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", true)]
    [InlineData("Ethernet 2", "VirtualBox Host-Only Ethernet Adapter", true)]
    [InlineData("Tailscale", "Tailscale Tunnel", true)]
    [InlineData("Ethernet", "Intel(R) Ethernet Connection I219-V", false)]
    [InlineData("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz", false)]
    public void Flags_virtual_adapters(string name, string desc, bool expected) =>
        Assert.Equal(expected, AdapterDiscovery.LooksVirtual(name, desc));

    [Fact]
    public void Recommends_physical_adapter_with_gateway_and_never_a_virtual_one()
    {
        var adapters = new[]
        {
            Adapter("vEthernet", "Hyper-V", virt: true, gateway: true),
            Adapter("Ethernet B", "Intel", virt: false, gateway: false),
            Adapter("Ethernet A", "Intel", virt: false, gateway: true),
        };

        Assert.Equal("Ethernet A", AdapterDiscovery.Recommend(adapters)!.Name);
        Assert.Null(AdapterDiscovery.Recommend([adapters[0]]));
    }
}
