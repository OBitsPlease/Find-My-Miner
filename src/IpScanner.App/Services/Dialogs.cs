using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;

namespace IpScanner.App.Services;

public static class Dialogs
{
    private static Window? Owner =>
        (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?
        .Windows.FirstOrDefault(w => w.IsActive)
        ?? (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;

    public static void Info(string message, string title = "Find My Miner") => Show(message, title);

    public static void Error(string message, string title = "Find My Miner") => Show(message, title);

    public static async Task<bool> ConfirmAsync(string message, string title = "Find My Miner")
    {
        var dialog = Create(message, title, confirm: true);
        return Owner is { } owner ? await dialog.ShowDialog<bool>(owner) : false;
    }

    private static void Show(string message, string title)
    {
        var dialog = Create(message, title, confirm: false);
        if (Owner is { } owner) _ = dialog.ShowDialog(owner);
        else dialog.Show();
    }

    private static Window Create(string message, string title, bool confirm)
    {
        var window = new Window
        {
            Title = title, Width = 520, SizeToContent = SizeToContent.Height,
            CanResize = false, WindowStartupLocation = WindowStartupLocation.CenterOwner
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right };
        if (confirm)
        {
            var yes = new Button { Content = "Yes", MinWidth = 80 };
            yes.Click += (_, _) => window.Close(true);
            buttons.Children.Add(yes);
        }
        var close = new Button { Content = confirm ? "No" : "OK", MinWidth = 80 };
        close.Click += (_, _) => window.Close(false);
        buttons.Children.Add(close);
        window.Content = new StackPanel
        {
            Margin = new Thickness(20), Spacing = 18,
            Children = { new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap }, buttons }
        };
        return window;
    }
}

public static class BrowserLauncher
{
    /// <summary>Opens http(s) URLs in the user's default browser. Credentials stay with that browser.</summary>
    public static bool Open(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            return false;

        try
        {
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
            return true;
        }

        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

}

public static class NotificationSound
{
    public static void Play()
    {
        try
        {
            if (OperatingSystem.IsWindows()) Console.Beep();
            else Console.Write('\a');
        }
        catch (Exception) { }
    }
}
