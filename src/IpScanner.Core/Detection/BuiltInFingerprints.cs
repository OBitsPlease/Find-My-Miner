namespace IpScanner.Core.Detection;

/// <summary>
/// Built-in fingerprints. These are heuristic: firmware varies, so they are weak-to-moderate
/// signals that combine into a score. Users can add their own rules in Settings.
/// </summary>
public static class BuiltInFingerprints
{
    public const string Jasminer = "Jasminer";
    public const string VolcMiner = "VolcMiner";
    public const string HiveOs = "HiveOS rig";
    public const string MinerDash = "Miner Dash";

    /// <summary>Evidence shared by every miner type; it supports the best specific match.</summary>
    public const string Generic = "Generic miner";

    public static IReadOnlyList<FingerprintRule> All { get; } =
    [
        new(Jasminer, EvidenceSource.Page, @"jasminer", 60, "Web page mentions Jasminer"),
        new(Jasminer, EvidenceSource.Page, @"jasminer[\s_-]*(?<model>x\d+(?:-[a-z0-9]+)?)", 20, "Jasminer model found on web page"),
        new(Jasminer, EvidenceSource.Page, @"sunlune", 30, "Web page mentions Sunlune (Jasminer maker)"),
        new(Jasminer, EvidenceSource.Hostname, @"jasminer", 50, "Hostname contains 'jasminer'"),

        new(VolcMiner, EvidenceSource.Page, @"volc[\s_-]*miner|火山矿机", 60, "Web page mentions VolcMiner"),
        new(VolcMiner, EvidenceSource.Page, @"volc[\s_-]*miner[\s_-]*(?<model>d\d+[a-z0-9-]*)", 20, "VolcMiner model found on web page"),
        new(VolcMiner, EvidenceSource.Hostname, @"volc[\s_-]*miner", 50, "Hostname contains 'volcminer'"),

        new(HiveOs, EvidenceSource.Page, @"hive[\s_-]?os|hiveon", 60, "Web page mentions HiveOS/Hiveon"),
        new(HiveOs, EvidenceSource.Port, @"^4200$", 25, "Port 4200 (Hive Shell) is open"),
        new(HiveOs, EvidenceSource.Page, @"shell[\s_-]*in[\s_-]*a[\s_-]*box", 35, "Shell In A Box page on port 4200 (Hive Shell)", Port: 4200),
        new(HiveOs, EvidenceSource.Hostname, @"hive", 20, "Hostname contains 'hive'"),

        new(MinerDash, EvidenceSource.Page, @"miner[\s_-]*dash(?:board)?", 60, "Web page mentions Miner Dash"),
        new(MinerDash, EvidenceSource.Hostname, @"miner[\s_-]*dash", 40, "Hostname contains 'minerdash'"),

        new(Generic, EvidenceSource.Api, @"cgminer|bmminer|sgminer|bfgminer|bosminer|luxminer|btminer|""API""\s*:", 50, "Answers a cgminer-style miner status API"),
        new(Generic, EvidenceSource.Port, @"^4028$", 15, "Port 4028 (miner API) is open"),
        new(Generic, EvidenceSource.Page, @"hash[\s_-]?rate|\b(?:th|gh|mh)/s\b|stratum|mining[\s_-]*pool", 20, "Web page mentions mining terms"),
        new(Generic, EvidenceSource.Hostname, @"\bminer\b|\basic\b|^(?:rig|worker)[-_]?\d*", 15, "Hostname looks like a miner or rig"),
    ];
}
