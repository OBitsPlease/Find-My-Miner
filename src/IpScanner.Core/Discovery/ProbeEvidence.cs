using System.Net;

namespace IpScanner.Core.Discovery;

/// <summary>What a single web service on a host returned for GET /.</summary>
public sealed record HttpEvidence(
    int Port,
    string Scheme,
    int StatusCode,
    string? Title,
    string? Server,
    string? Location,
    string? AuthRealm,
    string? CertSubject,
    bool CertTrusted,
    string BodySnippet);

/// <summary>Everything non-destructively learned about one responsive host.</summary>
public sealed record ProbeEvidence(
    IPAddress Address,
    string? Hostname,
    string? Mac,
    IReadOnlyList<int> OpenPorts,
    IReadOnlyList<HttpEvidence> Http,
    string? ApiBanner,
    TimeSpan? ResponseTime,
    DateTimeOffset SeenAt);
