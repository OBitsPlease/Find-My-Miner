using System.Collections.ObjectModel;
using System.Net.Sockets;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.Interactivity;
using IpScanner.App.Services;
using IpScanner.Core.Discovery;
using IpScanner.Core.Networking;

namespace IpScanner.App.Views;

public sealed record ReportRow(string Time, string From, string ReportedIp, string Mac, string Text, string TargetIp);

public partial class ListenWindow : Window
{
    private const int MaxRows = 200;

    private readonly ObservableCollection<ReportRow> _rows = [];
    private readonly Action<string, string> _openLogin;
    private readonly Action _scanNow;
    private CancellationTokenSource? _cts;

    public ListenWindow(Action<string, string> openLogin, Action scanNow)
    {
        InitializeComponent();
        _openLogin = openLogin;
        _scanNow = scanNow;
        ReportGrid.ItemsSource = _rows;
        ReportGrid.SelectionChanged += (_, _) => UpdateButtons();
        Closed += (_, _) => _cts?.Cancel();
    }

    private async void OnStartStop(object sender, RoutedEventArgs e)
    {
        if (_cts is not null)
        {
            _cts.Cancel();
            return;
        }

        if (!int.TryParse(PortBox.Text, out int port) || port is < 1 or > 65535)
        {
            Dialogs.Error("Enter a UDP port between 1 and 65535.");
            return;
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        PortBox.IsEnabled = false;
        StartButton.Content = "Stop";
        StatusText.Text = $"Listening on UDP {port}… press the IP button on the miner now.";

        try
        {
            await IpReportListener.ListenAsync(port, report => _ = HandleReportAsync(report), token);
            StatusText.Text = "Stopped.";
        }
        catch (SocketException ex)
        {
            StatusText.Text = "Could not listen.";
            var owner = UdpPortOwner.TryGetOwner(port);
            string who = owner is { } o
                ? $"It is already in use by {(o.Name is null ? "another program" : $"“{o.Name}”")} (process {o.Pid}). " +
                  "If that is an IP reporter tool, it may already be receiving the miner's report, so check it. " +
                  "Otherwise stop it temporarily, then press Start again."
                : "Another program may be using it.";
            Dialogs.Error($"Could not listen on UDP port {port}.\n\n{who}\n\n({ex.Message})");
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            PortBox.IsEnabled = true;
            StartButton.Content = "Start listening";
        }
    }

    private async Task HandleReportAsync(IpReport report)
    {
        string mac = report.ReportedMac ?? await ArpResolver.TryGetMacAsync(report.Sender) ?? string.Empty;
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            _rows.Insert(0, new ReportRow(
                report.ReceivedAt.LocalDateTime.ToString("T"),
                report.Sender.ToString(),
                report.ReportedIp?.ToString() ?? string.Empty,
                mac,
                report.Text,
                report.Target.ToString()));
            while (_rows.Count > MaxRows) _rows.RemoveAt(_rows.Count - 1);

            ReportGrid.SelectedIndex = 0;
            EmptyText.IsVisible = false;
            StatusText.Text = $"Received a report from {report.Sender}. You can now open its login page.";
            if (IsLoaded) NotificationSound.Play();
        });
    }

    private ReportRow? Selected => ReportGrid.SelectedItem as ReportRow;

    private void UpdateButtons() => OpenButton.IsEnabled = BrowserButton.IsEnabled = CopyButton.IsEnabled = Selected is not null;

    private void OnOpenLogin(object sender, RoutedEventArgs e)
    {
        if (Selected is { } row) _openLogin($"http://{row.TargetIp}/", row.TargetIp);
    }

    private void OnOpenBrowser(object sender, RoutedEventArgs e)
    {
        if (Selected is { } row && !BrowserLauncher.Open($"http://{row.TargetIp}/"))
            Dialogs.Error("Could not open your default browser.");
    }

    private async void OnCopyIp(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        await Clipboard!.SetTextAsync(row.TargetIp);
        StatusText.Text = "IP address copied.";
    }

    private void OnScanNow(object sender, RoutedEventArgs e)
    {
        _scanNow();
        StatusText.Text = "Scan started in the main window.";
    }
}
