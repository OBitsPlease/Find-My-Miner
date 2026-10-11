using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IpScanner.App.Services;
using IpScanner.App.Views;
using IpScanner.Core.Detection;
using IpScanner.Core.Discovery;
using IpScanner.Core.Export;
using IpScanner.Core.Networking;
using IpScanner.Core.Settings;
using Microsoft.Win32;

namespace IpScanner.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    public const string AllPlatforms = "All platforms";

    private readonly AppSettings _settings;
    private readonly SettingsStore _store;
    private readonly Dispatcher _ui = Dispatcher.UIThread;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(500) };
    private CancellationTokenSource? _cts;
    private DateTime _scanStart;
    private bool _hasBaseline;

    public MainViewModel(AppSettings settings, SettingsStore store)
    {
        _settings = settings;
        _store = store;
        _hasBaseline = settings.Devices.Count > 0;

        _timer.Tick += (_, _) => UpdateElapsed();
        RefreshAdapters();
    }

    public ObservableCollection<NetworkAdapterInfo> Adapters { get; } = [];
    public ObservableCollection<DeviceViewModel> Devices { get; } = [];
    public ObservableCollection<string> PlatformFilters { get; } = [AllPlatforms];
    public ObservableCollection<DeviceViewModel> View { get; } = [];

    [ObservableProperty] private NetworkAdapterInfo? _selectedAdapter;
    [ObservableProperty] private DeviceViewModel? _selectedDevice;
    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private string _selectedPlatformFilter = AllPlatforms;
    [ObservableProperty] private bool _minersOnly;
    [ObservableProperty] private bool _showIgnored;
    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private double _progressValue;
    [ObservableProperty] private double _progressMax = 1;
    [ObservableProperty] private string _statusText = "Ready. Choose a network and press Scan.";
    [ObservableProperty] private string _summaryText = "No scan yet";
    [ObservableProperty] private string _elapsedText = string.Empty;
    [ObservableProperty] private string _networkText = "No private network detected";

    public bool HasSelection => SelectedDevice is not null;
    public bool IsIdle => !IsScanning;
    public bool NoSelection => SelectedDevice is null;
    public bool NoDevices => Devices.Count == 0;

    partial void OnSelectedDeviceChanged(DeviceViewModel? value)
    {
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(NoSelection));
    }

    partial void OnSelectedAdapterChanged(NetworkAdapterInfo? value)
    {
        if (value is null)
        {
            NetworkText = "No private network detected. Connect to your LAN and refresh.";
        }
        else
        {
            string gateway = value.Gateway is null ? "no gateway" : $"gateway {value.Gateway}";
            NetworkText = $"Will scan {value.Subnet} · {value.Subnet.HostCount:N0} addresses · {gateway}" +
                          (value.IsVirtual ? " · virtual adapter" : string.Empty);
            _settings.PreferredAdapterId = value.Id;
        }

        ScanCommand.NotifyCanExecuteChanged();
    }

    partial void OnSearchTextChanged(string value) => RefreshView();
    partial void OnSelectedPlatformFilterChanged(string value) => RefreshView();
    partial void OnMinersOnlyChanged(bool value) => RefreshView();
    partial void OnShowIgnoredChanged(bool value) => RefreshView();

    partial void OnIsScanningChanged(bool value)
    {
        OnPropertyChanged(nameof(IsIdle));
        ScanCommand.NotifyCanExecuteChanged();
        CancelCommand.NotifyCanExecuteChanged();
        RescanUncertainCommand.NotifyCanExecuteChanged();
        RescanCommand.NotifyCanExecuteChanged();
    }

    // ---- Adapters ----------------------------------------------------------------------------

    [RelayCommand]
    private void RefreshAdapters()
    {
        var previous = SelectedAdapter;
        Adapters.Clear();
        foreach (var adapter in AdapterDiscovery.GetAdapters()) Adapters.Add(adapter);

        SelectedAdapter =
            Adapters.FirstOrDefault(a => previous is not null && a.Id == previous.Id && a.LocalAddress.Equals(previous.LocalAddress))
            ?? Adapters.FirstOrDefault(a => a.Id == _settings.PreferredAdapterId && !a.IsVirtual)
            ?? AdapterDiscovery.Recommend(Adapters)
            ?? Adapters.FirstOrDefault();
    }

    // ---- Scanning ----------------------------------------------------------------------------

    private bool CanScan() => !IsScanning && SelectedAdapter is not null;

    [RelayCommand(CanExecute = nameof(CanScan))]
    private async Task ScanAsync()
    {
        var adapter = SelectedAdapter!;
        var subnet = adapter.Subnet;
        var options = _settings.ToScanOptions();
        bool confirmed = false;

        var guard = ScanGuard.Check(subnet, options);
        if (guard.Verdict == GuardVerdict.Rejected)
        {
            var local = Subnet.Containing(adapter.LocalAddress, 24);
            if (subnet.IsPrivateRange && await Dialogs.ConfirmAsync(
                    $"{guard.Message}\n\nScan only the {local} range around your computer ({adapter.LocalAddress}) instead?"))
            {
                subnet = local;
            }
            else
            {
                if (!subnet.IsPrivateRange) Dialogs.Error(guard.Message);
                return;
            }
        }
        else if (guard.Verdict == GuardVerdict.NeedsConfirmation)
        {
            if (!await Dialogs.ConfirmAsync($"{guard.Message}\n\nScanning may take longer and generate more network traffic. Continue?"))
                return;
            confirmed = true;
        }

        var scanner = NewScanner();
        await RunAsync(
            $"Scanning {subnet}…",
            Devices.ToList(),
            async (callbacks, ct) =>
            {
                var macs = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>();
                var ipv4Callbacks = new ScanCallbacks
                {
                    OnDevice = d =>
                    {
                        if (d.Evidence.Mac is { } mac) macs[mac] = 0;
                        callbacks.OnDevice?.Invoke(d);
                    },
                    OnProgress = callbacks.OnProgress,
                };

                await scanner.ScanAsync(subnet, options, ipv4Callbacks, confirmed, ct);

                _ui.Post(() => StatusText = "Looking for IPv6-only devices…");
                await scanner.ScanIpv6Async(adapter, macs.Keys.ToHashSet(), options,
                    new ScanCallbacks { OnDevice = callbacks.OnDevice }, ct);
            });
    }

    [RelayCommand(CanExecute = nameof(IsScanning))]
    private void Cancel()
    {
        _cts?.Cancel();
        StatusText = "Cancelling…";
    }

    private bool CanRescan() => !IsScanning;

    [RelayCommand(CanExecute = nameof(CanRescan))]
    private Task RescanAsync(DeviceViewModel? device) =>
        device is null ? Task.CompletedTask : RescanDevicesAsync([device], $"Rescanning {device.Ip}…");

    [RelayCommand(CanExecute = nameof(CanRescan))]
    private Task RescanUncertainAsync()
    {
        var targets = Devices.Where(d => !d.IsOnline || d.Confidence <= Confidence.Possible).ToList();
        if (targets.Count == 0)
        {
            StatusText = "Nothing to rescan: every device is online and confidently identified.";
            return Task.CompletedTask;
        }

        return RescanDevicesAsync(targets, $"Rescanning {targets.Count} device(s)…");
    }

    private Task RescanDevicesAsync(IReadOnlyList<DeviceViewModel> targets, string label)
    {
        var hosts = targets.Select(t => t.Result.Evidence.Address).ToList();
        var options = _settings.ToScanOptions();
        var scanner = NewScanner();
        return RunAsync(label, targets, (callbacks, ct) => scanner.ScanHostsAsync(hosts, options, callbacks, ct));
    }

    private NetworkScanner NewScanner() => new(new HostProber(), new MinerDetector(_settings.AllRules()));

    private async Task RunAsync(string label, IReadOnlyCollection<DeviceViewModel> scope, Func<ScanCallbacks, CancellationToken, Task> run)
    {
        IsScanning = true;
        StatusText = label;
        ProgressValue = 0;
        ProgressMax = 1;
        _scanStart = DateTime.UtcNow;
        _timer.Start();
        UpdateElapsed();

        foreach (var device in scope)
        {
            device.IsOnline = false;
            device.IsNew = false;
            device.PreviousIp = null;
            device.PriorIp = device.Ip;
        }
        _cts = new CancellationTokenSource();
        var callbacks = new ScanCallbacks
        {
            OnDevice = result => _ui.Post(() => Merge(result)),
            OnProgress = (done, total) => _ui.Post(() =>
            {
                ProgressMax = Math.Max(1, total);
                ProgressValue = done;
                UpdateSummary();
            }),
        };

        string outcome;
        bool completed = false;
        try
        {
            await run(callbacks, _cts.Token);
            outcome = "Scan complete.";
            completed = true;
        }
        catch (OperationCanceledException)
        {
            outcome = "Scan cancelled.";
        }
        catch (ScanRejectedException ex)
        {
            outcome = $"Scan not started: {ex.Message}";
            Dialogs.Error(ex.Message);
        }
        catch (Exception ex)
        {
            outcome = $"Scan failed: {ex.Message}";
        }
        finally
        {
            // Let queued result callbacks land before finalising the summary.
            await _ui.InvokeAsync(() => { }, DispatcherPriority.Background);
            _timer.Stop();
            UpdateElapsed();
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;
        }

        _hasBaseline = true;
        if (completed) EvaluateIpChanges();
        Persist();
        UpdateSummary();
        int miners = Devices.Count(d => d.IsOnline && d.Confidence >= Confidence.Possible);
        StatusText = $"{outcome} Found {Devices.Count(d => d.IsOnline)} active host(s), {miners} likely miner(s).";
        RefreshView();
    }

    /// <summary>Flags a device as moved only if its previous IP no longer answers for any host in this scan.</summary>
    private void EvaluateIpChanges()
    {
        var currentIps = Devices.Where(d => d.IsOnline).Select(d => d.Ip).ToHashSet();
        foreach (var d in Devices.Where(d => d.IsOnline && d.Mac is not null && !d.IsIpv6Only))
        {
            if (d.PriorIp is { } prior && prior != d.Ip && !prior.Contains(':') && !currentIps.Contains(prior))
                d.PreviousIp = prior;
        }
    }

    private void Merge(DeviceResult result)
    {
        string ip = result.Evidence.Address.ToString();
        string key = result.Key;

        // A device already seen at another IP during this run shares the MAC (multi-IP host): keep it as its own row.
        var sameKey = Devices.FirstOrDefault(d => d.Key == key);
        if (sameKey is { IsOnline: true } && sameKey.Ip != ip) key = $"{key}@{ip}";

        var existing = Devices.FirstOrDefault(d => d.Key == key) ??
                       Devices.FirstOrDefault(d => d.Ip == ip && (d.Mac is null || result.Evidence.Mac is null));

        _settings.Devices.TryGetValue(key, out var known);
        if (known is null && result.Evidence.Mac is not null && key == result.Key && _settings.Devices.Remove(ip, out var byIp))
        {
            // The MAC became known: migrate the IP-keyed record so its name and flags survive.
            byIp.Key = key;
            byIp.Mac = result.Evidence.Mac;
            _settings.Devices[key] = known = byIp;
        }

        if (existing is null)
        {
            existing = new DeviceViewModel(result, key)
            {
                FriendlyName = known?.FriendlyName,
                TypeOverride = known?.PlatformOverride,
                RememberedPlatform = known?.Platform,
                IsIgnored = known?.Ignored ?? false,
                FirstSeen = known?.FirstSeen ?? DateTimeOffset.Now,
            };
            existing.PropertyChanged += OnDevicePropertyChanged;
            existing.PriorIp = known?.LastIp;
            existing.IsNew = _hasBaseline && known is null && existing.IsMinerLike;
            Devices.Add(existing);
            OnPropertyChanged(nameof(NoDevices));

            if (existing.IsNew && _settings.SoundOnNewMiner) NotificationSound.Play();
        }
        else
        {
            existing.Update(result);
        }

        UpsertKnown(existing);
        existing.RememberedPlatform = _settings.Devices[existing.Key].Platform;
        EnsurePlatformFilter(existing);
        RefreshView();
    }

    private void EnsurePlatformFilter(DeviceViewModel device)
    {
        if (device.IsMinerLike && !PlatformFilters.Contains(device.Platform)) PlatformFilters.Add(device.Platform);
    }

    private void UpsertKnown(DeviceViewModel device)
    {
        if (!_settings.Devices.TryGetValue(device.Key, out var known))
            _settings.Devices[device.Key] = known = new KnownDevice { Key = device.Key, FirstSeen = device.FirstSeen };

        known.Mac = device.Mac;
        known.LastIp = device.Ip;
        known.LastSeen = device.LastSeen;

        // Only solid, specific detections are remembered, so a weak scan never overwrites a good identification.
        if (PlatformResolver.ShouldRemember(device.Result.Detection)) known.Platform = device.Result.Detection.Platform;

        known.PlatformOverride = string.IsNullOrWhiteSpace(device.TypeOverride) ? null : device.TypeOverride!.Trim();
        known.FriendlyName = string.IsNullOrWhiteSpace(device.FriendlyName) ? null : device.FriendlyName!.Trim();
        known.Ignored = device.IsIgnored;
    }

    private void OnDevicePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not DeviceViewModel device) return;
        if (e.PropertyName is nameof(DeviceViewModel.FriendlyName) or nameof(DeviceViewModel.IsIgnored) or nameof(DeviceViewModel.TypeOverride))
        {
            UpsertKnown(device);
            EnsurePlatformFilter(device);
            Persist();
            RefreshView();
        }
    }

    // ---- Summary / filtering -----------------------------------------------------------------

    private void UpdateSummary()
    {
        int active = Devices.Count(d => d.IsOnline);
        int miners = Devices.Count(d => d.IsOnline && d.Confidence >= Confidence.Possible);
        SummaryText = IsScanning
            ? $"Scanned {ProgressValue:N0} of {ProgressMax:N0} · {active} active · {miners} likely miners"
            : $"{Devices.Count} device(s) listed · {active} online · {miners} likely miners";
    }

    private void UpdateElapsed() =>
        ElapsedText = IsScanning || _scanStart != default ? (DateTime.UtcNow - _scanStart).ToString(@"mm\:ss") : string.Empty;

    private bool FilterDevice(object item)
    {
        var d = (DeviceViewModel)item;
        if (!ShowIgnored && d.IsIgnored) return false;
        if (MinersOnly && !d.IsMinerLike) return false;
        if (SelectedPlatformFilter != AllPlatforms && d.Platform != SelectedPlatformFilter) return false;

        if (string.IsNullOrWhiteSpace(SearchText)) return true;
        string haystack = $"{d.Ip} {d.DisplayName} {d.Hostname} {d.Platform} {d.Model} {d.Mac} {d.PortsText}";
        return SearchText.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .All(t => haystack.Contains(t, StringComparison.OrdinalIgnoreCase));
    }

    private void RefreshView()
    {
        var filtered = Devices.Where(FilterDevice)
            .OrderByDescending(d => d.ConfidenceSort)
            .ThenBy(d => d.IpSort)
            .ToList();
        View.Clear();
        foreach (var device in filtered) View.Add(device);
    }

    // ---- Device actions ----------------------------------------------------------------------

    [RelayCommand]
    private void OpenEmbedded(DeviceViewModel? device)
    {
        if (device?.Url is null)
        {
            Dialogs.Info("No web interface was found on this device, so there is no login page to open.");
            return;
        }

        OpenLoginPage(device.Url, string.IsNullOrWhiteSpace(device.DisplayName) ? device.Ip : device.DisplayName);
    }

    private void OpenLoginPage(string url, string name)
    {
        new LoginWindow(url, name, _settings).Show(App.MainWindow);
    }

    [RelayCommand]
    private void OpenOffSubnet()
    {
        new OffSubnetWindow(_settings, Adapters.ToList(), SelectedAdapter, Persist, OnOffSubnetReached).Show(App.MainWindow);
    }

    /// <summary>After a temporary address makes another network reachable, scan it like any other.</summary>
    private void OnOffSubnetReached(OffSubnetDevice device)
    {
        RefreshAdapters();
        var target = Adapters.FirstOrDefault(a => a.Subnet.Contains(device.Address));
        if (target is null)
        {
            StatusText = "The new address is not active yet. Press Refresh, select the new network, and scan.";
            return;
        }

        SelectedAdapter = target;
        if (ScanCommand.CanExecute(null)) ScanCommand.Execute(null);
    }

    public bool HasTemporaryAddresses => _settings.TemporaryAddresses.Count > 0;

    /// <summary>Offers to remove temporary addresses before the app closes; declining keeps them for next time.</summary>
    public async Task OfferRemoveTemporaryAddressesAsync()
    {
        if (!await Dialogs.ConfirmAsync(
                "Find My Miner added temporary network addresses (" +
                string.Join(", ", _settings.TemporaryAddresses.Select(r => r.Address)) +
                ") so it could reach a miner on another network.\n\nRemove them now? Windows will ask for administrator permission."))
            return;

        var result = await TemporaryAddressService.RemoveAllAsync(_settings);
        Persist();
        if (result.Outcome == ElevatedOutcome.Failed) Dialogs.Error($"The addresses could not be removed:\n{result.Message}");
    }

    [RelayCommand]
    private void OpenIpReport()
    {
        var window = new ListenWindow(OpenLoginPage, () =>
        {
            if (ScanCommand.CanExecute(null)) ScanCommand.Execute(null);
        });
        window.Show(App.MainWindow);
    }

    [RelayCommand]
    private void OpenBrowser(DeviceViewModel? device)
    {
        if (device?.Url is null)
        {
            Dialogs.Info("No web interface was found on this device.");
            return;
        }

        if (!BrowserLauncher.Open(device.Url)) Dialogs.Error("Could not open your default browser.");
    }

    [RelayCommand]
    private void CopyIp(DeviceViewModel? device) => SetClipboard(device?.Ip, "IP address copied.");

    [RelayCommand]
    private void CopyUrl(DeviceViewModel? device) => SetClipboard(device?.Url, "Login URL copied.");

    [RelayCommand]
    private void CopyAllUrls()
    {
        var urls = View.Where(d => d.Url is not null && d.Confidence >= Confidence.Possible)
            .Select(d => d.Url!).ToList();
        SetClipboard(string.Join(Environment.NewLine, urls), $"Copied {urls.Count} miner URL(s).");
    }

    [RelayCommand]
    private void ToggleIgnore(DeviceViewModel? device)
    {
        if (device is not null) device.IsIgnored = !device.IsIgnored;
    }

    [RelayCommand]
    private async Task EditDeviceAsync(DeviceViewModel? device)
    {
        if (device is null) return;

        var window = new EditDeviceWindow(device.Ip, device.FriendlyName, device.TypeOverride,
            device.Result.Detection.Platform, PlatformFilters.Where(p => p != AllPlatforms));
        if (await window.ShowDialog<bool>(App.MainWindow) != true) return;

        device.FriendlyName = window.DeviceName;
        device.TypeOverride = window.DeviceType;
        StatusText = "Saved.";
    }

    private void SetClipboard(string? text, string message)
    {
        if (string.IsNullOrEmpty(text)) return;
        try
        {
            _ = App.MainWindow.Clipboard!.SetTextAsync(text);
            StatusText = message;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            StatusText = "The clipboard is busy; try again.";
        }
    }

    // ---- Export / settings / theme -----------------------------------------------------------

    [RelayCommand]
    private async Task ExportAsync()
    {
        var rows = View.Select(d => d.ToExportRow()).ToList();
        if (rows.Count == 0)
        {
            Dialogs.Info("There are no results to export.");
            return;
        }

        var file = await App.MainWindow.StorageProvider.SaveFilePickerAsync(new()
        {
            Title = "Export scan results",
            SuggestedFileName = $"miners-{DateTime.Now:yyyyMMdd-HHmm}.csv",
            FileTypeChoices =
            [
                new("CSV file") { Patterns = ["*.csv"] },
                new("JSON file") { Patterns = ["*.json"] },
            ],
        });
        if (file is null) return;

        try
        {
            string path = file.Path.LocalPath;
            string content = path.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ? ResultExporter.ToJson(rows) : ResultExporter.ToCsv(rows);
            await System.IO.File.WriteAllTextAsync(path, content);
            StatusText = $"Exported {rows.Count} row(s) to {path}";
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
            Dialogs.Error($"Could not save the file:\n{ex.Message}");
        }
    }

    [RelayCommand]
    private void ToggleTheme()
    {
        _settings.Theme = ThemeService.IsDark ? "Light" : "Dark";
        ApplyTheme();
        Persist();
    }

    [RelayCommand]
    private async Task OpenSettingsAsync()
    {
        var working = SettingsStore.Clone(_settings);
        var window = new SettingsWindow(working);
        if (await window.ShowDialog<bool>(App.MainWindow) != true) return;

        _settings.CopyFrom(working);
        ApplyTheme();

        foreach (var device in Devices)
        {
            bool stillKnown = _settings.Devices.ContainsKey(device.Key);
            if (!stillKnown)
            {
                device.FriendlyName = null;
                device.IsIgnored = false;
                device.TypeOverride = null;
                device.RememberedPlatform = null;
            }
        }

        _hasBaseline = _settings.Devices.Count > 0;
        Persist();
        StatusText = "Settings saved.";
    }

    private void ApplyTheme()
    {
        ThemeService.Apply(_settings.Theme);
        foreach (var device in Devices) device.Update(device.Result);
    }

    private void Persist()
    {
        try { _store.Save(_settings); }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
            StatusText = $"Could not save settings: {ex.Message}";
        }
    }

    public void Shutdown()
    {
        _cts?.Cancel();
        Persist();
    }
}
