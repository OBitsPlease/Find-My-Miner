using System.Net;

namespace IpScanner.Core.Discovery;

/// <summary>Chooses the management URL to offer for a device.</summary>
public static class UrlSelector
{
    private static readonly int[] PortPreference = [80, 443, 8080, 8443, 8888, 1337, 4200];

    /// <summary>
    /// Builds a URL from the scanned IP and port only. A redirect's scheme and port are honoured
    /// only when it points back at the same host, so a device cannot steer the user elsewhere.
    /// </summary>
    public static string? Choose(ProbeEvidence evidence, int? preferredPort = null)
    {
        // Browsers cannot open link-local IPv6 URLs (zone ids are unsupported), so no link is better than a broken one.
        if (evidence.Http.Count == 0 || evidence.Address.IsIPv6LinkLocal) return null;

        // The web service that actually triggered the detection beats generic port preference.
        var best = (preferredPort is int wanted ? evidence.Http.FirstOrDefault(h => h.Port == wanted && h.StatusCode < 500) : null)
            ?? evidence.Http
                .OrderBy(h => h.StatusCode >= 500)
                .ThenBy(h => PreferenceRank(h.Port))
                .ThenBy(h => h.Port)
                .First();

        string scheme = best.Scheme;
        int port = best.Port;

        if (best.Location is { Length: > 0 } location &&
            Uri.TryCreate(location, UriKind.Absolute, out var target) &&
            target.Scheme is "http" or "https" &&
            IPAddress.TryParse(target.Host, out var targetIp) &&
            targetIp.Equals(evidence.Address))
        {
            scheme = target.Scheme;
            port = target.Port;
        }

        return Build(scheme, evidence.Address, port);
    }

    public static string Build(string scheme, IPAddress address, int port)
    {
        string host = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{address}]"
            : address.ToString();
        bool isDefault = (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
        return isDefault ? $"{scheme}://{host}/" : $"{scheme}://{host}:{port}/";
    }

    private static int PreferenceRank(int port)
    {
        int index = Array.IndexOf(PortPreference, port);
        return index < 0 ? PortPreference.Length : index;
    }
}
