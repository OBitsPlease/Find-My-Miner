using System.Net;
using IpScanner.Core.Detection;
using IpScanner.Core.Discovery;
using IpScanner.Core.Settings;

namespace IpScanner.Core.Tests;

public class MinerDetectorTests
{
    private static readonly MinerDetector Detector = new();

    private static ProbeEvidence Evidence(
        string? title = null, string body = "", string? hostname = null, int[]? ports = null,
        string? api = null, int httpPort = 80, string? server = null, string? realm = null)
    {
        var http = title is null && body.Length == 0 && realm is null
            ? []
            : new List<HttpEvidence> { new(httpPort, "http", 200, title, server, null, realm, null, true, $"<html><title>{title}</title>{body}</html>") };
        return new ProbeEvidence(IPAddress.Parse("192.168.1.50"), hostname, "AA:BB:CC:00:11:22",
            ports ?? [80], http, api, TimeSpan.FromMilliseconds(3), DateTimeOffset.Now);
    }

    [Fact]
    public void Identifies_jasminer_with_model()
    {
        var r = Detector.Detect(Evidence("JASMINER X4-Q High-throughput Mini Server", ports: [22, 80, 4028]));
        Assert.Equal(BuiltInFingerprints.Jasminer, r.Platform);
        Assert.Equal("X4-Q", r.Model);
        Assert.Equal(Confidence.Confirmed, r.Confidence);
    }

    [Fact]
    public void Identifies_volcminer_with_model()
    {
        var r = Detector.Detect(Evidence("VolcMiner D1", ports: [80, 4028]));
        Assert.Equal(BuiltInFingerprints.VolcMiner, r.Platform);
        Assert.Equal("D1", r.Model);
        Assert.True(r.Confidence >= Confidence.Likely);
    }

    [Fact]
    public void Identifies_hiveos_from_page_text()
    {
        var r = Detector.Detect(Evidence("Hive OS Rig", ports: [22, 80]));
        Assert.Equal(BuiltInFingerprints.HiveOs, r.Platform);
        Assert.True(r.Confidence >= Confidence.Likely);
    }

    [Fact]
    public void Identifies_hive_shell_from_port_and_page()
    {
        var r = Detector.Detect(Evidence("Shell In A Box", ports: [22, 4200], httpPort: 4200));
        Assert.Equal(BuiltInFingerprints.HiveOs, r.Platform);
        Assert.True(r.Confidence >= Confidence.Likely);
    }

    [Fact]
    public void Open_hive_shell_port_alone_is_only_possible()
    {
        var r = Detector.Detect(Evidence(ports: [22, 4200]));
        Assert.Equal(BuiltInFingerprints.HiveOs, r.Platform);
        Assert.Equal(Confidence.Possible, r.Confidence);
    }

    [Fact]
    public void Identifies_miner_dash()
    {
        var r = Detector.Detect(Evidence("MinerDash - Login", ports: [80]));
        Assert.Equal(BuiltInFingerprints.MinerDash, r.Platform);
        Assert.True(r.Confidence >= Confidence.Likely);
    }

    [Fact]
    public void Unbranded_cgminer_api_is_a_generic_miner()
    {
        const string api = "{\"STATUS\":[{\"STATUS\":\"S\"}],\"VERSION\":[{\"CGMiner\":\"4.11.1\",\"API\":\"3.7\"}]}";
        var r = Detector.Detect(Evidence(ports: [4028], api: api));
        Assert.Equal(BuiltInFingerprints.Generic, r.Platform);
        Assert.True(r.Confidence >= Confidence.Likely);
    }

    [Fact]
    public void Specific_vendor_beats_generic_api_and_gains_confidence()
    {
        const string api = "{\"VERSION\":[{\"CGMiner\":\"4.11.1\"}]}";
        var r = Detector.Detect(Evidence("Jasminer", ports: [80, 4028], api: api));
        Assert.Equal(BuiltInFingerprints.Jasminer, r.Platform);
        Assert.Equal(Confidence.Confirmed, r.Confidence);
    }

    [Theory]
    [InlineData("TP-Link Wireless Router", "<form>Login to your router</form>", "tplinkwifi.net")]
    [InlineData("HP LaserJet Pro M404", "Printer status", "NPI1A2B3C")]
    [InlineData("Camera Login", "IP camera web service", null)]
    [InlineData(null, "", "DESKTOP-4F2K")]
    public void Ordinary_devices_are_not_miners(string? title, string body, string? hostname)
    {
        var r = Detector.Detect(Evidence(title, body, hostname, ports: [22, 80, 443]));
        Assert.Equal(Confidence.Unknown, r.Confidence);
        Assert.Equal(DetectionResult.UnknownPlatform, r.Platform);
    }

    [Fact]
    public void Custom_rules_extend_detection_and_bad_patterns_are_ignored()
    {
        var custom = new CustomFingerprint
        {
            Name = "Basement rigs", Platform = "Miner Dash", Source = EvidenceSource.Hostname, Pattern = "^basement-", Weight = 70,
        };
        var bad = new CustomFingerprint { Name = "bad", Platform = "X", Pattern = "([unclosed", Weight = 99 };
        var detector = new MinerDetector(BuiltInFingerprints.All.Concat([custom.ToRule(), bad.ToRule()]));

        var r = detector.Detect(Evidence(hostname: "basement-03", ports: [80]));
        Assert.Equal("Miner Dash", r.Platform);
        Assert.Equal(Confidence.Likely, r.Confidence);
    }

    [Theory]
    [InlineData(0, Confidence.Unknown)]
    [InlineData(14, Confidence.Unknown)]
    [InlineData(15, Confidence.Possible)]
    [InlineData(50, Confidence.Likely)]
    [InlineData(80, Confidence.Confirmed)]
    public void Maps_scores_to_confidence(int score, Confidence expected) =>
        Assert.Equal(expected, MinerDetector.ToConfidence(score));
}
