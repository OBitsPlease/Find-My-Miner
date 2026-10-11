using IpScanner.Core.Detection;

namespace IpScanner.Core.Tests;

public class PlatformResolverTests
{
    private static DetectionResult Detected(string platform, Confidence confidence, int score = 60) =>
        new(platform, null, score, confidence, ["reason"]);

    [Fact]
    public void A_weaker_scan_does_not_erase_a_remembered_identification()
    {
        var generic = Detected(BuiltInFingerprints.Generic, Confidence.Possible, 15);
        var r = PlatformResolver.Resolve(generic, remembered: BuiltInFingerprints.Jasminer, userSet: null);

        Assert.Equal(BuiltInFingerprints.Jasminer, r.Platform);
        Assert.Equal(PlatformSource.Remembered, r.Source);
        Assert.Contains("earlier scan", r.Note);
    }

    [Fact]
    public void Unknown_scans_also_fall_back_to_the_remembered_platform()
    {
        var r = PlatformResolver.Resolve(DetectionResult.Unknown, BuiltInFingerprints.VolcMiner, null);
        Assert.Equal(BuiltInFingerprints.VolcMiner, r.Platform);
    }

    [Fact]
    public void Fresh_specific_evidence_beats_memory()
    {
        var r = PlatformResolver.Resolve(Detected(BuiltInFingerprints.HiveOs, Confidence.Likely), BuiltInFingerprints.Jasminer, null);
        Assert.Equal(BuiltInFingerprints.HiveOs, r.Platform);
        Assert.Equal(PlatformSource.Detected, r.Source);
    }

    [Fact]
    public void The_users_choice_always_wins()
    {
        var r = PlatformResolver.Resolve(Detected(BuiltInFingerprints.HiveOs, Confidence.Confirmed, 100), BuiltInFingerprints.Jasminer, "  Jasminer X4  ");
        Assert.Equal("Jasminer X4", r.Platform);
        Assert.Equal(Confidence.Confirmed, r.Confidence);
        Assert.Equal(PlatformSource.UserSet, r.Source);
    }

    [Fact]
    public void Generic_or_blank_memory_is_ignored()
    {
        Assert.Equal(DetectionResult.UnknownPlatform, PlatformResolver.Resolve(DetectionResult.Unknown, BuiltInFingerprints.Generic, null).Platform);
        Assert.Equal(DetectionResult.UnknownPlatform, PlatformResolver.Resolve(DetectionResult.Unknown, "  ", null).Platform);
    }

    [Theory]
    [InlineData("Jasminer", Confidence.Likely, true)]
    [InlineData("Jasminer", Confidence.Possible, false)]
    [InlineData("Generic miner", Confidence.Confirmed, false)]
    [InlineData("Unknown device", Confidence.Unknown, false)]
    public void Only_strong_specific_detections_are_remembered(string platform, Confidence confidence, bool expected) =>
        Assert.Equal(expected, PlatformResolver.ShouldRemember(Detected(platform, confidence)));
}
