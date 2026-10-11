namespace IpScanner.Core.Detection;

public enum Confidence
{
    Unknown = 0,
    Possible = 1,
    Likely = 2,
    Confirmed = 3,
}

public enum EvidenceSource
{
    /// <summary>Page title, page body and auth realm combined.</summary>
    Page,
    Title,
    Header,
    Realm,
    Certificate,
    Hostname,
    Port,
    Api,
}

/// <summary>
/// A data-driven detection rule. A pattern with a named group "model" also yields the device model.
/// </summary>
public sealed record FingerprintRule(
    string Platform,
    EvidenceSource Source,
    string Pattern,
    int Weight,
    string Reason,
    int? Port = null);

public sealed record DetectionResult(
    string Platform,
    string? Model,
    int Score,
    Confidence Confidence,
    IReadOnlyList<string> Reasons,
    int? MatchedPort = null)
{
    public const string UnknownPlatform = "Unknown device";

    public static DetectionResult Unknown { get; } =
        new(UnknownPlatform, null, 0, Confidence.Unknown, ["No mining-specific signals were found."]);

    public bool IsMinerLike => Confidence >= Confidence.Possible;
}
