using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using IpScanner.App.ViewModels;
using IpScanner.Core.Settings;

namespace IpScanner.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private bool _closeApproved;

    public MainWindow(AppSettings settings, SettingsStore store)
    {
        InitializeComponent();
        _viewModel = new MainViewModel(settings, store);
        DataContext = _viewModel;
        Closing += OnClosing;
    }

    private async void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_closeApproved && _viewModel.HasTemporaryAddresses)
        {
            e.Cancel = true;
            await _viewModel.OfferRemoveTemporaryAddressesAsync();
            _closeApproved = true;
            Close();
            return;
        }

        _viewModel.Shutdown();
    }

    private void OnGridDoubleClick(object sender, Avalonia.Input.TappedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is DeviceViewModel { HasUrl: true } device)
        {
            _viewModel.OpenEmbeddedCommand.Execute(device);
        }
    }

    // Right-click selects the row under the cursor so the context menu acts on it.
    private void OnGridRightClick(object sender, Avalonia.Input.PointerPressedEventArgs e) { }

    private void OnGridKeyDown(object sender, Avalonia.Input.KeyEventArgs e)
    {
        if (e.Key == Avalonia.Input.Key.F2 && _viewModel.SelectedDevice is { } device)
        {
            _viewModel.EditDeviceCommand.Execute(device);
            e.Handled = true;
        }
    }

    private void OnMenuEdit(object sender, RoutedEventArgs e) => _viewModel.EditDeviceCommand.Execute(_viewModel.SelectedDevice);
    private void OnMenuOpen(object sender, RoutedEventArgs e) => _viewModel.OpenEmbeddedCommand.Execute(_viewModel.SelectedDevice);
    private void OnMenuBrowser(object sender, RoutedEventArgs e) => _viewModel.OpenBrowserCommand.Execute(_viewModel.SelectedDevice);
    private void OnMenuCopyIp(object sender, RoutedEventArgs e) => _viewModel.CopyIpCommand.Execute(_viewModel.SelectedDevice);
    private void OnMenuRescan(object sender, RoutedEventArgs e) => _viewModel.RescanCommand.Execute(_viewModel.SelectedDevice);
    private void OnMenuIgnore(object sender, RoutedEventArgs e) => _viewModel.ToggleIgnoreCommand.Execute(_viewModel.SelectedDevice);
}
