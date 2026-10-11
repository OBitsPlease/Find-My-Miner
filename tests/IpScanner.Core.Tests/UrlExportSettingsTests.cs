using System.Net;
using IpScanner.Core.Discovery;
using IpScanner.Core.Export;
using IpScanner.Core.Settings;

namespace IpScanner.Core.Tests;

public class UrlSelectorTests
{
    private static ProbeEvidence Evidence(params HttpEvidence[] http) =>
        new(IPAddress.Parse("192.168.1.50"), null, null, http.Select(h => h.Port).ToList(), http, null, null, DateTimeOffset.Now);

    private static HttpEvidence Http(int port, string scheme = "http", int status = 200, string? location = null) =>
        new(port, scheme, status, null, null, location, null, null, true, string.Empty);

    [Fact]
    public void Returns_null_without_a_web_service() => Assert.Null(UrlSelector.Choose(Evidence()));

    [Fact]
    public void Prefers_port_80_and_omits_default_port() =>
        Assert.Equal("http://192.168.1.50/", UrlSelector.Choose(Evidence(Http(8080), Http(80))));

    [Fact]
    public void Includes_non_default_port() =>
        Assert.Equal("https://192.168.1.50:8443/", UrlSelector.Choose(Evidence(Http(8443, "https"))));

    [Fact]
    public void Follows_same_host_redirect_to_https() =>
        Assert.Equal("https://192.168.1.50/", UrlSelector.Choose(Evidence(Http(80, status: 301, location: "https://192.168.1.50/login"))));

    [Fact]
    public void Ignores_redirects_to_other_hosts() =>
        Assert.Equal("http://192.168.1.50/", UrlSelector.Choose(Evidence(Http(80, status: 302, location: "https://evil.example/"))));

    [Fact]
    public void Avoids_server_error_pages_when_alternatives_exist() =>
        Assert.Equal("http://192.168.1.50:8080/", UrlSelector.Choose(Evidence(Http(80, status: 503), Http(8080))));

    [Fact]
    public void Prefers_the_port_that_matched_the_detection() =>
        Assert.Equal("https://192.168.1.50:8443/", UrlSelector.Choose(Evidence(Http(8080), Http(8443, "https")), preferredPort: 8443));

    [Fact]
    public void Detector_reports_the_matching_web_port()
    {
        var evidence = new ProbeEvidence(
            IPAddress.Parse("192.168.1.50"), null, null, [8080, 8443],
            [
                new HttpEvidence(8080, "http", 200, "Solo Pools Dashboard", null, null, null, null, true, "<title>Solo Pools Dashboard</title>"),
                new HttpEvidence(8443, "https", 200, "Miner Dash", null, null, null, null, true, "<title>Miner Dash</title>"),
            ],
            null, null, DateTimeOffset.Now);

        var detection = new IpScanner.Core.Detection.MinerDetector().Detect(evidence);
        Assert.Equal(8443, detection.MatchedPort);
        Assert.Equal("https://192.168.1.50:8443/", UrlSelector.Choose(evidence, detection.MatchedPort));
    }
}

public class ExporterAndSettingsTests
{
    private static ExportRow Row(string? hostname = "rig-1") =>
        new("192.168.1.50", hostname, null, "AA:BB:CC:00:11:22", "Jasminer", "X4", "Confirmed", 100,
            "http://192.168.1.50/", "80;4028", DateTimeOffset.Parse("2026-10-01T22:00:00Z"));

    [Theory]
    [InlineData("=HYPERLINK(\"x\")", "\"'=HYPERLINK(\"\"x\"\")\"")]
    [InlineData("+1+1", "'+1+1")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("plain", "plain")]
    [InlineData(null, "")]
    public void Escapes_csv_and_blocks_formula_injection(string? input, string expected) =>
        Assert.Equal(expected, ResultExporter.Escape(input));

    [Fact]
    public void Csv_has_header_and_row()
    {
        var lines = ResultExporter.ToCsv([Row()]).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.StartsWith("IP,Hostname", lines[0]);
        Assert.Contains("192.168.1.50,rig-1", lines[1]);
    }

    [Fact]
    public void Json_contains_url() => Assert.Contains("http://192.168.1.50/", ResultExporter.ToJson([Row()]));

    [Fact]
    public void Settings_round_trip_and_hold_no_credential_fields()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ipscanner-{Guid.NewGuid():N}", "settings.json");
        try
        {
            var store = new SettingsStore(path);
            var s = new AppSettings { Theme = "Light", MaxConcurrency = 32 };
            s.Devices["AA:BB"] = new KnownDevice { Key = "AA:BB", LastIp = "192.168.1.9", FriendlyName = "Rig 1" };
            s.CustomFingerprints.Add(new CustomFingerprint { Name = "n", Pattern = "x", Port = 3333 });
            store.Save(s);

            var loaded = store.Load();
            Assert.Equal("Light", loaded.Theme);
            Assert.Equal("Rig 1", loaded.Devices["AA:BB"].FriendlyName);
            Assert.Equal(3333, loaded.CustomFingerprints[0].Port);

            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
            string[] secretNames = ["password", "username", "credentials", "cookies", "token", "secret"];
            Assert.DoesNotContain(doc.RootElement.EnumerateObject(),
                p => secretNames.Contains(p.Name, StringComparer.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Fact]
    public void Corrupt_settings_fall_back_to_defaults()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "{ not json");
            Assert.Equal("Dark", new SettingsStore(path).Load().Theme);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Custom_fingerprint_ports_are_added_to_scan_options()
    {
        var s = new AppSettings();
        s.CustomFingerprints.Add(new CustomFingerprint { Pattern = "x", Port = 3333 });
        var o = s.ToScanOptions();
        Assert.Contains(3333, o.Ports);
        Assert.Contains(3333, o.WebPorts);
    }
}
