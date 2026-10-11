using IpScanner.Core.Detection;
using IpScanner.Core.Discovery;

namespace IpScanner.Core.Settings;

/// <summary>A user-defined detection rule. Nothing here is sensitive.</summary>
public sealed class CustomFingerprint
{
    public string Name { get; set; } = "My miner";
    public string Platform { get; set; } = "Miner Dash";
    public EvidenceSource Source { get; set; } = EvidenceSource.Page;
    public string Pattern { get; set; } = string.Empty;
    public int? Port { get; set; }
    public int Weight { get; set; } = 60;

    public FingerprintRule ToRule() =>
        new(Platform, Source, Pattern, Math.Clamp(Weight, 1, 100), $"Custom rule: {Name}", Port);
}

/// <summary>An IPv4 address this app added to an adapter so a device on another network could be reached.</summary>
public sealed class TemporaryAddressRecord
{
    public int InterfaceIndex { get; set; }
    public string Address { get; set; } = string.Empty;
    public int PrefixLength { get; set; } = 24;
    public string? ForDevice { get; set; }
    public DateTimeOffset AddedAt { get; set; } = DateTimeOffset.Now;
}

public sealed class KnownDevice
{
    public string Key { get; set; } = string.Empty;
    public string? Mac { get; set; }
    public string LastIp { get; set; } = string.Empty;
    public string? FriendlyName { get; set; }
    public bool Ignored { get; set; }

    /// <summary>The strongest specific platform ever detected for this device.</summary>
    public string? Platform { get; set; }

    /// <summary>A type chosen by the user; always wins over detection.</summary>
    public string? PlatformOverride { get; set; }
    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.Now;
}

/// <summary>Persisted preferences. Never contains passwords, cookies or page content.</summary>
public sealed class AppSettings
{
    public string Theme { get; set; } = "Dark";
    public string? PreferredAdapterId { get; set; }

    public int MaxConcurrency { get; set; } = 64;
    public int ConnectTimeoutMs { get; set; } = 800;
    public int HttpTimeoutMs { get; set; } = 3000;

    /// <summary>Lets the embedded browser offer to save logins (stored by WebView2, not by this app).</summary>
    public bool OfferPasswordSave { get; set; } = true;

    public bool SoundOnNewMiner { get; set; } = true;

    public List<CustomFingerprint> CustomFingerprints { get; set; } = [];
    public Dictionary<string, KnownDevice> Devices { get; set; } = [];

    /// <summary>Temporary addresses added by the app, remembered so they can be removed later.</summary>
    public List<TemporaryAddressRecord> TemporaryAddresses { get; set; } = [];

    public void CopyFrom(AppSettings other)
    {
        Theme = other.Theme;
        PreferredAdapterId = other.PreferredAdapterId;
        MaxConcurrency = other.MaxConcurrency;
        ConnectTimeoutMs = other.ConnectTimeoutMs;
        HttpTimeoutMs = other.HttpTimeoutMs;
        OfferPasswordSave = other.OfferPasswordSave;
        SoundOnNewMiner = other.SoundOnNewMiner;
        CustomFingerprints = other.CustomFingerprints;
        Devices = other.Devices;
        TemporaryAddresses = other.TemporaryAddresses;
    }

    public ScanOptions ToScanOptions() =>
        new ScanOptions
        {
            MaxConcurrentHosts = MaxConcurrency,
            ConnectTimeout = TimeSpan.FromMilliseconds(ConnectTimeoutMs),
            HttpTimeout = TimeSpan.FromMilliseconds(HttpTimeoutMs),
        }
        .WithExtraWebPorts(CustomFingerprints.Where(c => c.Port is not null).Select(c => c.Port!.Value))
        .Normalized();

    public IEnumerable<FingerprintRule> AllRules() =>
        BuiltInFingerprints.All.Concat(
            CustomFingerprints.Where(c => !string.IsNullOrWhiteSpace(c.Pattern)).Select(c => c.ToRule()));
}
