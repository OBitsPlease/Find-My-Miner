using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using IpScanner.Core.Detection;

namespace IpScanner.App.Views;

public partial class EditDeviceWindow : Window
{
    private const string Automatic = "(detect automatically)";

    public EditDeviceWindow(string ip, string? name, string? typeOverride, string detectedPlatform, IEnumerable<string> knownPlatforms)
    {
        InitializeComponent();
        HeaderText.Text = $"Device {ip}";
        NameBox.Text = name ?? string.Empty;

        var types = new List<string>
        {
            Automatic,
            BuiltInFingerprints.Jasminer,
            BuiltInFingerprints.VolcMiner,
            BuiltInFingerprints.HiveOs,
            BuiltInFingerprints.MinerDash,
            BuiltInFingerprints.Generic,
        };
        types.AddRange(knownPlatforms.Where(p => !types.Contains(p, StringComparer.OrdinalIgnoreCase)));
        TypeBox.ItemsSource = types;
        TypeBox.Text = string.IsNullOrWhiteSpace(typeOverride) ? Automatic : typeOverride;

        DetectedText.Text = $"Detected by the scanner: {detectedPlatform}. Choose a type, or type your own such as “VolcMiner D1”.";
        Loaded += (_, _) => NameBox.Focus();
    }

    public string? DeviceName { get; private set; }
    public string? DeviceType { get; private set; }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        string name = NameBox.Text?.Trim() ?? string.Empty;
        string type = TypeBox.Text?.Trim() ?? string.Empty;

        DeviceName = name.Length == 0 ? null : name;
        DeviceType = type.Length == 0 || type.Equals(Automatic, StringComparison.OrdinalIgnoreCase) ? null : type;
        Close(true);
    }
}
