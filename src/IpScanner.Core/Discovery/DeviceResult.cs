using System.Net;
using IpScanner.Core.Detection;

namespace IpScanner.Core.Discovery;

public sealed record DeviceResult(ProbeEvidence Evidence, DetectionResult Detection, string? ManagementUrl)
{
    /// <summary>Stable identity: MAC when known (survives DHCP changes), otherwise the IP.</summary>
    public string Key => Evidence.Mac ?? Evidence.Address.ToString();
}

public sealed class ScanCallbacks
{
    public Action<DeviceResult>? OnDevice { get; init; }
    public Action<IPAddress>? OnMiss { get; init; }

    /// <summary>Called with (scanned, total) after each host completes.</summary>
    public Action<int, int>? OnProgress { get; init; }
}
