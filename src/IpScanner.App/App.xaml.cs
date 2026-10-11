using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using IpScanner.Core.Settings;

namespace IpScanner.App;

public partial class App : Application
{
    public static Window MainWindow =>
        ((IClassicDesktopStyleApplicationLifetime)Current!.ApplicationLifetime!).MainWindow!;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var store = new SettingsStore(SettingsStore.DefaultPath);
            var settings = store.Load();
            Services.ThemeService.Apply(settings.Theme);
            desktop.MainWindow = new MainWindow(settings, store);
        }
        base.OnFrameworkInitializationCompleted();
    }
}
