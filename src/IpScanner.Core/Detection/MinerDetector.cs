using System.Text.RegularExpressions;
using IpScanner.Core.Discovery;

namespace IpScanner.Core.Detection;

/// <summary>Scores probe evidence against fingerprint rules and picks the best explanation.</summary>
public sealed class MinerDetector
{
    public const int PossibleThreshold = 15;
    public const int LikelyThreshold = 50;
    public const int ConfirmedThreshold = 80;

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private readonly List<(FingerprintRule Rule, Regex Regex)> _rules = [];

    public MinerDetector(IEnumerable<FingerprintRule>? rules = null)
    {
        foreach (var rule in rules ?? BuiltInFingerprints.All)
        {
            if (string.IsNullOrWhiteSpace(rule.Platform) || string.IsNullOrWhiteSpace(rule.Pattern) || rule.Weight <= 0)
                continue;

            try
            {
                _rules.Add((rule, new Regex(rule.Pattern,
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline, RegexTimeout)));
            }
            catch (ArgumentException)
            {
                // A malformed user-supplied pattern must never break scanning.
            }
        }
    }

    public DetectionResult Detect(ProbeEvidence evidence)
    {
        var scores = new Dictionary<string, Score>(StringComparer.OrdinalIgnoreCase);

        foreach (var (rule, regex) in _rules)
        {
            var hit = FindMatch(regex, rule, evidence);
            if (hit is null) continue;
            var (match, matchedPort) = hit.Value;

            if (!scores.TryGetValue(rule.Platform, out var score))
                scores[rule.Platform] = score = new Score();

            score.Total += rule.Weight;
            score.Reasons.Add(rule.Reason);
            score.Port ??= matchedPort;

            var model = match.Groups["model"];
            if (model.Success && score.Model is null)
                score.Model = model.Value.Trim().ToUpperInvariant();
        }

        scores.TryGetValue(BuiltInFingerprints.Generic, out var generic);
        var specific = scores
            .Where(kv => !kv.Key.Equals(BuiltInFingerprints.Generic, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(kv => kv.Value.Total)
            .Select(kv => (Platform: kv.Key, Score: kv.Value))
            .FirstOrDefault();

        string platform;
        Score best;
        int total;
        if (specific.Score is not null && specific.Score.Total >= PossibleThreshold)
        {
            platform = specific.Platform;
            best = specific.Score;
            total = best.Total + (generic?.Total ?? 0);
        }
        else if (generic is not null)
        {
            platform = BuiltInFingerprints.Generic;
            best = generic;
            total = generic.Total;
        }
        else
        {
            return DetectionResult.Unknown;
        }

        var reasons = best.Reasons.Concat(generic is not null && best != generic ? generic.Reasons : [])
            .Distinct().ToList();
        total = Math.Min(100, total);

        return new DetectionResult(platform, best.Model, total, ToConfidence(total), reasons, best.Port ?? generic?.Port);
    }

    public static Confidence ToConfidence(int score) => score switch
    {
        >= ConfirmedThreshold => Confidence.Confirmed,
        >= LikelyThreshold => Confidence.Likely,
        >= PossibleThreshold => Confidence.Possible,
        _ => Confidence.Unknown,
    };

    private static (Match Match, int? Port)? FindMatch(Regex regex, FingerprintRule rule, ProbeEvidence evidence)
    {
        try
        {
            foreach (var (text, port) in Corpus(rule, evidence))
            {
                var match = regex.Match(text);
                if (match.Success) return (match, port);
            }
        }
        catch (RegexMatchTimeoutException)
        {
        }

        return null;
    }

    private static IEnumerable<(string Text, int? Port)> Corpus(FingerprintRule rule, ProbeEvidence ev)
    {
        var http = rule.Port is int port ? ev.Http.Where(h => h.Port == port) : ev.Http;

        switch (rule.Source)
        {
            case EvidenceSource.Page:
                foreach (var h in http)
                {
                    yield return (h.BodySnippet, h.Port);
                    if (h.Title is not null) yield return (h.Title, h.Port);
                    if (h.AuthRealm is not null) yield return (h.AuthRealm, h.Port);
                }
                break;
            case EvidenceSource.Title:
                foreach (var h in http.Where(h => h.Title is not null)) yield return (h.Title!, h.Port);
                break;
            case EvidenceSource.Header:
                foreach (var h in http.Where(h => h.Server is not null)) yield return (h.Server!, h.Port);
                break;
            case EvidenceSource.Realm:
                foreach (var h in http.Where(h => h.AuthRealm is not null)) yield return (h.AuthRealm!, h.Port);
                break;
            case EvidenceSource.Certificate:
                foreach (var h in http.Where(h => h.CertSubject is not null)) yield return (h.CertSubject!, h.Port);
                break;
            case EvidenceSource.Hostname:
                if (ev.Hostname is not null) yield return (ev.Hostname, null);
                break;
            case EvidenceSource.Port:
                foreach (var p in ev.OpenPorts) yield return (p.ToString(), null);
                break;
            case EvidenceSource.Api:
                if (ev.ApiBanner is not null) yield return (ev.ApiBanner, null);
                break;
        }
    }

    private sealed class Score
    {
        public int Total;
        public string? Model;
        public int? Port;
        public List<string> Reasons { get; } = [];
    }
}
