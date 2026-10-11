namespace IpScanner.Core.Detection;

public enum PlatformSource { Detected, Remembered, UserSet }

/// <summary>The platform to show for a device after combining fresh detection, memory of past scans, and the user's choice.</summary>
public sealed record ResolvedPlatform(string Platform, Confidence Confidence, PlatformSource Source, string? Note);

public static class PlatformResolver
{
    public static bool IsSpecific(string? platform) =>
        !string.IsNullOrWhiteSpace(platform) &&
        !platform.Equals(BuiltInFingerprints.Generic, StringComparison.OrdinalIgnoreCase) &&
        !platform.Equals(DetectionResult.UnknownPlatform, StringComparison.OrdinalIgnoreCase);

    /// <summary>Only strong, specific identifications are worth remembering for later scans.</summary>
    public static bool ShouldRemember(DetectionResult detection) =>
        detection.Confidence >= Confidence.Likely && IsSpecific(detection.Platform);

    public static ResolvedPlatform Resolve(DetectionResult detection, string? remembered, string? userSet)
    {
        if (!string.IsNullOrWhiteSpace(userSet))
            return new(userSet.Trim(), Confidence.Confirmed, PlatformSource.UserSet, "You set this device's type.");

        // A scan that only sees a generic or empty signal (for example while a miner is still booting)
        // must not erase an earlier solid identification.
        if (IsSpecific(remembered) && !IsSpecific(detection.Platform))
            return new(remembered!, Confidence.Likely, PlatformSource.Remembered,
                $"Remembered from an earlier scan; this scan found weaker evidence ({detection.Platform}).");

        return new(detection.Platform, detection.Confidence, PlatformSource.Detected, null);
    }
}
