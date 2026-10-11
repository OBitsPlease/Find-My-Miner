using System.IO;
using System.Net;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using IpScanner.App.Services;
using IpScanner.Core.Networking;
using IpScanner.Core.Settings;

namespace IpScanner.App.Views;

public partial class OffSubnetWindow : Window
{
    private readonly AppSettings _settings;
    private readonly Action _persist;
    private readonly Action<OffSubnetDevice> _onReached;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private DateTime _started;
    private bool _busy;

    public OffSubnetWindow(
        AppSettings settings,
        IReadOnlyList<NetworkAdapterInfo> adapters,
        NetworkAdapterInfo? selected,
        Action persist,
        Action<OffSubnetDevice> onReached)
    {
        InitializeComponent();
        _settings = settings;
        _persist = persist;
        _onReached = onReached;

        AdapterBox.ItemsSource = adapters.Where(a => a.InterfaceIndex > 0).ToList();
        AdapterBox.SelectedItem = selected is not null && adapters.Contains(selected) ? selected : AdapterBox.Items.Cast<object>().FirstOrDefault();
        DeviceGrid.SelectionChanged += (_, _) => UpdateButtons();
        _timer.Tick += (_, _) => UpdateProgressText();
        UpdateTemporaryText();
        UpdateButtons();
    }

    private NetworkAdapterInfo? Adapter => AdapterBox.SelectedItem as NetworkAdapterInfo;
    private OffSubnetDevice? Selected => DeviceGrid.SelectedItem as OffSubnetDevice;

    private string? _workDir;

    // The elevated script writes a marker when it starts, so we can tell "waiting for permission" from "capturing".
    private void UpdateProgressText()
    {
        string? marker = _workDir is null ? null : Path.Combine(_workDir, OffSubnetDiscovery.StartedFileName);
        if (marker is null || !File.Exists(marker))
        {
            StatusText.Text = "Waiting for you to approve the Windows permission prompt…";
            return;
        }

        int elapsed = (int)(DateTime.UtcNow - File.GetCreationTimeUtc(marker)).TotalSeconds;
        StatusText.Text = elapsed < OffSubnetDiscovery.DefaultSeconds
            ? $"Capturing… {Math.Max(elapsed, 0)} of {OffSubnetDiscovery.DefaultSeconds} seconds. Press the miner's IP button or replug its cable now."
            : "Processing the capture…";
    }

    private void UpdateButtons()
    {
        bool addressed = Selected is { IsAddressless: false };
        ReachButton.IsEnabled = !_busy && addressed && Adapter is not null;
        CopyButton.IsEnabled = addressed;
        StartButton.IsEnabled = !_busy;
        RemoveButton.IsEnabled = !_busy && _settings.TemporaryAddresses.Count > 0;
    }

    private void UpdateTemporaryText() =>
        TempText.Text = _settings.TemporaryAddresses.Count == 0
            ? "No temporary addresses added by Find My Miner."
            : "Added by Find My Miner: " + string.Join(", ", _settings.TemporaryAddresses.Select(
                r => $"{r.Address}/{r.PrefixLength}{(r.ForDevice is null ? string.Empty : $" (for {r.ForDevice})")}"));

    private async void OnStart(object sender, RoutedEventArgs e)
    {
        _busy = true;
        UpdateButtons();
        EmptyText.IsVisible = false;
        _started = DateTime.UtcNow;
        _timer.Start();

        string dir = ElevatedPowerShell.NewWorkDirectory();
        _workDir = dir;
        try
        {
            string script = OffSubnetDiscovery.BuildCaptureScript(dir, OffSubnetDiscovery.DefaultSeconds);
            var result = await ElevatedPowerShell.RunAsync(
                script, Path.Combine(dir, OffSubnetDiscovery.StatusFileName),
                TimeSpan.FromSeconds(OffSubnetDiscovery.DefaultSeconds + 120), CancellationToken.None);

            if (result.Outcome != ElevatedOutcome.Succeeded)
            {
                StatusText.Text = result.Outcome == ElevatedOutcome.Cancelled ? "Cancelled: permission was not granted." : "The capture failed.";
                if (result.Outcome == ElevatedOutcome.Failed)
                    Dialogs.Error($"The capture could not be completed.\n\n{result.Message}\n\nThe Windows Packet Monitor (pktmon) is required.");
                return;
            }

            string file = Path.Combine(dir, OffSubnetDiscovery.CaptureFileName);
            IReadOnlyList<OffSubnetDevice> devices = File.Exists(file)
                ? OffSubnetDiscovery.Parse(File.ReadLines(file), AdapterDiscovery.GetLocalSubnets())
                : [];

            DeviceGrid.ItemsSource = devices;
            EmptyText.Text = "Nothing was heard from any device without a normal address. If the miner was just plugged in, wait a few minutes (miners can take a minute or two to boot), then try again. Also check the network link lights and the cable.";
            EmptyText.IsVisible = devices.Count == 0;
            StatusText.Text = devices.Count == 0 ? "Capture complete: nothing found." : $"Found {devices.Count} device(s) on other networks.";
            if (devices.Count > 0) DeviceGrid.SelectedIndex = 0;
        }
        finally
        {
            _timer.Stop();
            _workDir = null;
            ElevatedPowerShell.TryDelete(dir);
            _busy = false;
            UpdateButtons();
        }
    }

    private async void OnReach(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } device || Adapter is not { } adapter) return;

        var local = AdapterDiscovery.GetLocalSubnets();
        var address = TemporaryAddress.Pick(device.Address, local);
        if (address is null)
        {
            Dialogs.Info("This PC already has an address on that network, so the device should be reachable. Select that network in the main window and scan it.");
            _onReached(device);
            return;
        }

        if (!await Dialogs.ConfirmAsync(
                $"Add the temporary address {address}/{TemporaryAddress.DefaultPrefix} to “{adapter.Name}”?\n\n" +
                $"This lets this PC reach {device.Address} directly. Your existing addresses are not changed, and you can remove it again here. " +
                "Windows will ask for administrator permission."))
            return;

        _busy = true;
        UpdateButtons();
        StatusText.Text = "Adding the temporary address…";
        string dir = ElevatedPowerShell.NewWorkDirectory();
        try
        {
            string status = Path.Combine(dir, OffSubnetDiscovery.StatusFileName);
            var result = await ElevatedPowerShell.RunAsync(
                TemporaryAddress.BuildAddScript(adapter.InterfaceIndex, address, TemporaryAddress.DefaultPrefix, status),
                status, TimeSpan.FromSeconds(90), CancellationToken.None);

            if (result.Outcome != ElevatedOutcome.Succeeded)
            {
                StatusText.Text = result.Outcome == ElevatedOutcome.Cancelled ? "Cancelled: permission was not granted." : "Could not add the address.";
                if (result.Outcome == ElevatedOutcome.Failed) Dialogs.Error($"The address could not be added.\n\n{result.Message}");
                return;
            }

            _settings.TemporaryAddresses.Add(new TemporaryAddressRecord
            {
                InterfaceIndex = adapter.InterfaceIndex,
                Address = address.ToString(),
                PrefixLength = TemporaryAddress.DefaultPrefix,
                ForDevice = device.Address.ToString(),
            });
            _persist();
            UpdateTemporaryText();
            StatusText.Text = $"Added {address}. Scanning {device.Address}'s network in the main window…";
            _onReached(device);
        }
        finally
        {
            ElevatedPowerShell.TryDelete(dir);
            _busy = false;
            UpdateButtons();
        }
    }

    private async void OnRemove(object sender, RoutedEventArgs e)
    {
        if (!await Dialogs.ConfirmAsync("Remove the temporary addresses Find My Miner added? Do this once the miner is back on your normal network. Windows will ask for administrator permission."))
            return;

        _busy = true;
        UpdateButtons();
        StatusText.Text = "Removing…";
        try
        {
            var result = await TemporaryAddressService.RemoveAllAsync(_settings);
            _persist();
            UpdateTemporaryText();
            StatusText.Text = result.Outcome switch
            {
                ElevatedOutcome.Succeeded => "Temporary addresses removed.",
                ElevatedOutcome.Cancelled => "Cancelled: permission was not granted.",
                _ => $"Could not remove: {result.Message}",
            };
        }
        finally
        {
            _busy = false;
            UpdateButtons();
        }
    }

    private async void OnCopy(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } d) return;
        await Clipboard!.SetTextAsync(d.Address.ToString());
        StatusText.Text = "IP address copied.";
    }
}
