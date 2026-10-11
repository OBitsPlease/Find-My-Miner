using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using IpScanner.App.Services;
using IpScanner.Core.Detection;
using IpScanner.Core.Settings;

namespace IpScanner.App.Views;

public partial class SettingsWindow : Window
{
    private readonly AppSettings _working;
    private readonly ObservableCollection<CustomFingerprint> _rules;

    public SettingsWindow(AppSettings working)
    {
        InitializeComponent();
        _working = working;
        _rules = new ObservableCollection<CustomFingerprint>(working.CustomFingerprints);

        ThemeBox.ItemsSource = ThemeService.Themes;
        ThemeBox.SelectedItem = ThemeService.Themes.Contains(working.Theme) ? working.Theme : "Dark";
        ConcurrencySlider.Value = working.MaxConcurrency;
        ConnectSlider.Value = working.ConnectTimeoutMs;
        HttpSlider.Value = working.HttpTimeoutMs;
        SoundBox.IsChecked = working.SoundOnNewMiner;

        RulesGrid.ItemsSource = _rules;
    }

    private async void OnForgetDevices(object sender, RoutedEventArgs e)
    {
        if (!await Dialogs.ConfirmAsync("Forget every remembered device name, ignored flag and first-seen date? This takes effect when you press Save."))
            return;

        _working.Devices = [];
    }

    private void OnAddRule(object sender, RoutedEventArgs e)
    {
        var rule = new CustomFingerprint { Name = "New rule", Platform = "Miner Dash", Pattern = string.Empty };
        _rules.Add(rule);
        RulesGrid.SelectedItem = rule;
        RulesGrid.ScrollIntoView(rule, null);
    }

    private void OnRemoveRule(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is CustomFingerprint rule) _rules.Remove(rule);
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        RulesGrid.CommitEdit(DataGridEditingUnit.Row, true);

        foreach (var rule in _rules.Where(r => !string.IsNullOrWhiteSpace(r.Pattern)))
        {
            try { _ = new System.Text.RegularExpressions.Regex(rule.Pattern); }
            catch (ArgumentException ex)
            {
                Dialogs.Error($"The pattern for rule “{rule.Name}” is not a valid regular expression:\n{ex.Message}");
                return;
            }

            if (rule.Port is < 1 or > 65535)
            {
                Dialogs.Error($"The port for rule “{rule.Name}” must be between 1 and 65535.");
                return;
            }
        }

        _working.Theme = ThemeBox.SelectedItem as string ?? "Dark";
        _working.MaxConcurrency = (int)ConcurrencySlider.Value;
        _working.ConnectTimeoutMs = (int)ConnectSlider.Value;
        _working.HttpTimeoutMs = (int)HttpSlider.Value;
        _working.OfferPasswordSave = false;
        _working.SoundOnNewMiner = SoundBox.IsChecked == true;
        _working.CustomFingerprints = _rules.Where(r => !string.IsNullOrWhiteSpace(r.Pattern)).ToList();

        Close(true);
    }
}
