using Avalonia;
using Avalonia.Media;
using Avalonia.Styling;

namespace IpScanner.App.Services;

/// <summary>Applies the Fluent light/dark theme plus the app's own card and status brushes.</summary>
public static class ThemeService
{
    public static readonly string[] Themes = ["System", "Light", "Dark"];

    public static bool IsDark { get; private set; } = true;

    public static void Apply(string theme)
    {
        var app = Application.Current;
        app!.RequestedThemeVariant = theme switch
        {
            "Light" => ThemeVariant.Light,
            "System" => ThemeVariant.Default,
            _ => ThemeVariant.Dark,
        };

        IsDark = theme switch
        {
            "Light" => false,
            "System" => app.ActualThemeVariant == ThemeVariant.Dark,
            _ => true,
        };

        var r = app.Resources;
        r["CardBrush"] = Brush(IsDark ? "#2A2F38" : "#FFFFFF");
        r["CardBorderBrush"] = Brush(IsDark ? "#3A424F" : "#D5DCE6");
        r["SubtleTextBrush"] = Brush(IsDark ? "#9DA9B9" : "#586374");
        r["AccentBrush"] = Brush(IsDark ? "#4FB0FF" : "#0B6BCB");
        r["ConfirmedBrush"] = Brush("#2EA043");
        r["LikelyBrush"] = Brush(IsDark ? "#4FB0FF" : "#0B6BCB");
        r["PossibleBrush"] = Brush("#D29922");
        r["UnknownBrush"] = Brush(IsDark ? "#7B8794" : "#8A94A3");
        r["WarnBrush"] = Brush("#E5A50A");
        r["BadBrush"] = Brush("#E5534B");
        r["SelectedRowBrush"] = Brush(IsDark ? "#23527F" : "#D6E8FB");
        r["SelectedTextBrush"] = Brush(IsDark ? "#FFFFFF" : "#101820");
    }

    private static SolidColorBrush Brush(string hex)
    {
        return new SolidColorBrush(Color.Parse(hex));
    }
}
