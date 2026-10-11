using Avalonia.Controls;
using Avalonia.Interactivity;
using IpScanner.App.Services;
using IpScanner.Core.Settings;

namespace IpScanner.App.Views;

public partial class LoginWindow : Window
{
    private readonly string _url;

    public LoginWindow(string url, string deviceName, AppSettings settings)
    {
        InitializeComponent();
        _url = url;
        Title = $"{deviceName} — system browser";
        AddressText.Text = url;
        Opened += (_, _) =>
        {
            if (!BrowserLauncher.Open(_url))
                Dialogs.Error("Could not open your default browser.");
        };
    }

    private void OnOpenExternal(object? sender, RoutedEventArgs e)
    {
        if (!BrowserLauncher.Open(_url))
            Dialogs.Error("Could not open your default browser.");
    }

    private void OnClose(object? sender, RoutedEventArgs e) => Close();
}
