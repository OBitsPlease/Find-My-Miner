namespace IpScanner.Core.Discovery;

public sealed record ScanOptions
{
    public IReadOnlyList<int> Ports { get; init; } = [22, 80, 443, 1337, 4028, 4200, 8080, 8443, 8888];
    public IReadOnlyList<int> WebPorts { get; init; } = [80, 443, 1337, 4200, 8080, 8443, 8888];
    public IReadOnlyList<int> HttpsPorts { get; init; } = [443, 8443];

    /// <summary>Port for the read-only miner status API (cgminer-style).</summary>
    public int ApiPort { get; init; } = 4028;

    public int MaxConcurrentHosts { get; init; } = 64;
    public TimeSpan PingTimeout { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromMilliseconds(800);
    public TimeSpan HttpTimeout { get; init; } = TimeSpan.FromSeconds(3);
    public TimeSpan ApiTimeout { get; init; } = TimeSpan.FromSeconds(1.5);
    public TimeSpan DnsTimeout { get; init; } = TimeSpan.FromSeconds(1.5);
    public TimeSpan HostTimeout { get; init; } = TimeSpan.FromSeconds(15);

    public int MaxBodyBytes { get; init; } = 16 * 1024;

    /// <summary>Hard cap on addresses per scan.</summary>
    public int MaxHosts { get; init; } = 1024;

    /// <summary>Permits loopback targets. Intended for automated tests only.</summary>
    public bool AllowLoopback { get; init; }

    public const int MinConcurrency = 1;
    public const int MaxConcurrency = 256;

    /// <summary>Returns a copy with all values clamped to safe bounds.</summary>
    public ScanOptions Normalized() => this with
    {
        MaxConcurrentHosts = Math.Clamp(MaxConcurrentHosts, MinConcurrency, MaxConcurrency),
        ConnectTimeout = Clamp(ConnectTimeout, 100, 10_000),
        PingTimeout = Clamp(PingTimeout, 100, 5_000),
        HttpTimeout = Clamp(HttpTimeout, 500, 30_000),
        ApiTimeout = Clamp(ApiTimeout, 200, 10_000),
        DnsTimeout = Clamp(DnsTimeout, 200, 10_000),
        HostTimeout = Clamp(HostTimeout, 1_000, 60_000),
        MaxBodyBytes = Math.Clamp(MaxBodyBytes, 1024, 256 * 1024),
        MaxHosts = Math.Clamp(MaxHosts, 1, 4096),
    };

    /// <summary>Adds user-defined ports to both the probe list and the web-probe list.</summary>
    public ScanOptions WithExtraWebPorts(IEnumerable<int> ports)
    {
        var extra = ports.Where(p => p is > 0 and <= 65535).ToArray();
        return this with
        {
            Ports = Ports.Union(extra).Order().ToArray(),
            WebPorts = WebPorts.Union(extra).Order().ToArray(),
        };
    }

    private static TimeSpan Clamp(TimeSpan value, double minMs, double maxMs) =>
        TimeSpan.FromMilliseconds(Math.Clamp(value.TotalMilliseconds, minMs, maxMs));
}
