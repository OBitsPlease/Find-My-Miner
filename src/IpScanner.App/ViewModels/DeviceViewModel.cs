using Avalonia;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using IpScanner.Core.Detection;
using IpScanner.Core.Discovery;
using IpScanner.Core.Export;
using IpScanner.Core.Networking;

namespace IpScanner.App.ViewModels;

public sealed partial class DeviceViewModel : ObservableObject
{
    [ObservableProperty] private DeviceResult _result;
    [ObservableProperty] private string? _friendlyName;
    [ObservableProperty] private bool _isIgnored;
    [ObservableProperty] private bool _isOnline = true;
    [ObservableProperty] private bool _isNew;
    [ObservableProperty] private string? _previousIp;

    /// <summary>A type the user chose in "Name &amp; type"; overrides detection.</summary>
    [ObservableProperty] private string? _typeOverride;

    /// <summary>The strongest platform identified in an earlier scan.</summary>
    [ObservableProperty] private string? _rememberedPlatform;

    /// <summary>The IP this device had at the start of the current scan (or when last remembered).</summary>
    public string? PriorIp { get; set; }
    [ObservableProperty] private DateTimeOffset _firstSeen = DateTimeOffset.Now;

    public DeviceViewModel(DeviceResult result, string key)
    {
        _result = result;
        Key = key;
    }

    public void Update(DeviceResult result)
    {
        Result = result;
        IsOnline = true;
        OnPropertyChanged(string.Empty);
    }

    /// <summary>Stable identity: MAC (or IP). A second IP answering with an already-seen MAC gets "mac@ip".</summary>
    public string Key { get; }
    public string Ip => Result.Evidence.Address.ToString();
    public bool IsIpv6Only => Result.Evidence.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
    public uint IpSort => IsIpv6Only ? uint.MaxValue : Subnet.ToUInt(Result.Evidence.Address);
    public string? Ipv6Note => IsIpv6Only
        ? "Found over IPv6 only. This device has no IPv4 address on your network, so its web page cannot be opened. " +
          "Restart it, check your router's DHCP leases, or give it a static IPv4 address, then rescan."
        : null;
    public string? Hostname => Result.Evidence.Hostname;
    public string DisplayName => !string.IsNullOrWhiteSpace(FriendlyName) ? FriendlyName! : ShortHostname;
    private ResolvedPlatform Resolved => PlatformResolver.Resolve(Result.Detection, RememberedPlatform, TypeOverride);
    private string ShortHostname => Hostname is null ? string.Empty : Hostname.Split('.')[0];
    public string Platform => Resolved.Platform;
    public string Model => Resolved.Source == PlatformSource.Detected ? Result.Detection.Model ?? string.Empty : string.Empty;
    public Confidence Confidence => Resolved.Confidence;
    public int ConfidenceSort => (int)Confidence * 1000 + (Resolved.Source == PlatformSource.Detected ? Result.Detection.Score : 0);
    public string ConfidenceText => Resolved.Source switch
    {
        PlatformSource.UserSet => "Set by you",
        PlatformSource.Remembered => "Remembered",
        _ => Confidence == Confidence.Unknown ? "—" : $"{Confidence} · {Result.Detection.Score}%",
    };
    public string? Mac => Result.Evidence.Mac;
    public string MacText => Mac ?? string.Empty;
    public string PortsText => string.Join(", ", Result.Evidence.OpenPorts);
    public string LatencyText => Result.Evidence.ResponseTime is { } t ? $"{Math.Max(1, (int)t.TotalMilliseconds)} ms" : string.Empty;
    public string? Url => Result.ManagementUrl;
    public bool HasUrl => Url is not null;
    public IReadOnlyList<string> Reasons => Resolved.Note is null ? Result.Detection.Reasons : [Resolved.Note, .. Result.Detection.Reasons];
    public bool IsMinerLike => Confidence >= Confidence.Possible;
    public DateTimeOffset LastSeen => Result.Evidence.SeenAt;
    public string LastSeenText => LastSeen.LocalDateTime.ToString("g");
    public string FirstSeenText => FirstSeen.LocalDateTime.ToString("g");

    public string HeadlineText => Confidence == Confidence.Unknown
        ? "Unidentified device"
        : $"{Platform}{(Model.Length > 0 ? " " + Model : string.Empty)}";

    public string? CertificateWarning => Result.Evidence.Http.Any(h => h.Scheme == "https" && !h.CertTrusted)
        ? "HTTPS certificate is not trusted (typical for miners with a self-signed certificate)."
        : null;

    public string? IpChangeNote => PreviousIp is null ? null : $"Previously seen at {PreviousIp}";

    public string StatusText => !IsOnline ? "Offline" : IsIpv6Only ? "IPv6 only" : IsNew ? "New" : PreviousIp is not null ? "IP changed" : "Online";

    public IBrush StatusBrush => GetBrush(
        !IsOnline ? "UnknownBrush" : IsIpv6Only ? "WarnBrush" : IsNew ? "AccentBrush" : PreviousIp is not null ? "WarnBrush" : "ConfirmedBrush");

    public IBrush ConfidenceBrush => GetBrush(Confidence switch
    {
        Confidence.Confirmed => "ConfirmedBrush",
        Confidence.Likely => "LikelyBrush",
        Confidence.Possible => "PossibleBrush",
        _ => "UnknownBrush",
    });

    private static IBrush GetBrush(string key) =>
        Application.Current?.Resources.TryGetResource(key, null, out var value) == true && value is IBrush brush
            ? brush
            : Brushes.Gray;

    public ExportRow ToExportRow() => new(
        Ip, Hostname, FriendlyName, Mac, Platform, Result.Detection.Model, Confidence.ToString(),
        Result.Detection.Score, Url, string.Join(';', Result.Evidence.OpenPorts), LastSeen);

    partial void OnFriendlyNameChanged(string? value) => OnPropertyChanged(nameof(DisplayName));
    partial void OnTypeOverrideChanged(string? value) => RefreshIdentity();
    partial void OnRememberedPlatformChanged(string? value) => RefreshIdentity();

    private void RefreshIdentity()
    {
        foreach (var name in new[]
                 {
                     nameof(Platform), nameof(Model), nameof(Confidence), nameof(ConfidenceSort), nameof(ConfidenceText),
                     nameof(ConfidenceBrush), nameof(Reasons), nameof(HeadlineText), nameof(IsMinerLike),
                 })
            OnPropertyChanged(name);
    }

    partial void OnIsOnlineChanged(bool value) => RefreshStatus();
    partial void OnIsNewChanged(bool value) => RefreshStatus();
    partial void OnPreviousIpChanged(string? value)
    {
        OnPropertyChanged(nameof(IpChangeNote));
        RefreshStatus();
    }

    private void RefreshStatus()
    {
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(StatusBrush));
    }
}
