using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Discovery;

public interface IHostProber
{
    /// <summary>Returns evidence for a responsive host, or null when nothing answered.</summary>
    Task<ProbeEvidence?> ProbeAsync(IPAddress address, ScanOptions options, CancellationToken cancellationToken);
}

/// <summary>
/// Non-destructive prober: TCP connects, a single GET / per web port, a read-only "version"
/// query on the miner API port, reverse DNS and ARP. No credentials are ever sent.
/// </summary>
public sealed partial class HostProber : IHostProber
{
    [GeneratedRegex(@"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline, matchTimeoutMilliseconds: 250)]
    private static partial Regex TitleRegex();

    [GeneratedRegex(@"realm\s*=\s*""?([^"",]+)", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 250)]
    private static partial Regex RealmRegex();

    public async Task<ProbeEvidence?> ProbeAsync(IPAddress address, ScanOptions options, CancellationToken cancellationToken)
    {
        // ARP answers even when a device blocks ping and has no open probe ports, so it counts as discovery.
        var macTask = ArpResolver.TryGetMacAsync(address);
        var pingTask = PingAsync(address, options.PingTimeout, cancellationToken);
        var connectTasks = options.Ports.Distinct()
            .Select(async port => (Port: port, Elapsed: await TryConnectAsync(address, port, options.ConnectTimeout, cancellationToken)))
            .ToArray();

        var connects = await Task.WhenAll(connectTasks);
        var pingTime = await pingTask;
        string? mac = await macTask;
        cancellationToken.ThrowIfCancellationRequested();

        var open = connects.Where(c => c.Elapsed is not null).Select(c => c.Port).Order().ToList();
        var connectTimes = connects.Where(c => c.Elapsed is not null).Select(c => c.Elapsed!.Value).ToList();

        // Small embedded devices (miners) sometimes drop part of the first burst of connection attempts. If a host is
        // clearly alive but no web port was found, give its ports a slower second chance before giving up.
        bool alive = pingTime is not null || mac is not null;
        if (alive && !open.Any(options.WebPorts.Contains))
        {
            var retried = await ConnectGentlyAsync(address, options.Ports.Distinct().Except(open).ToList(), options, cancellationToken);
            open = open.Union(retried.Select(r => r.Port)).Order().ToList();
            connectTimes.AddRange(retried.Select(r => r.Elapsed));
        }

        if (open.Count == 0 && pingTime is null && mac is null) return null;

        TimeSpan? responseTime = pingTime ?? (connectTimes.Count > 0 ? connectTimes.Min() : null);

        using var hostCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        hostCts.CancelAfter(options.HostTimeout);
        var token = hostCts.Token;

        var httpTasks = open.Where(options.WebPorts.Contains)
            .Select(port => ProbeHttpAsync(address, port, options, token)).ToList();
        var apiTask = open.Contains(options.ApiPort)
            ? ReadMinerApiAsync(address, options, token)
            : Task.FromResult<string?>(null);
        var dnsTask = ResolveHostnameAsync(address, options.DnsTimeout, token);

        var http = (await Task.WhenAll(httpTasks)).Where(h => h is not null).Select(h => h!)
            .OrderBy(h => h.Port).ToList();
        string? api = await apiTask;
        string? hostname = await dnsTask;
        cancellationToken.ThrowIfCancellationRequested();

        return new ProbeEvidence(address, hostname, mac, open, http, api, responseTime, DateTimeOffset.Now);
    }

    private static async Task<List<(int Port, TimeSpan Elapsed)>> ConnectGentlyAsync(
        IPAddress address, IReadOnlyList<int> ports, ScanOptions options, CancellationToken ct)
    {
        var found = new List<(int, TimeSpan)>();
        if (ports.Count == 0) return found;

        await Task.Delay(300, ct);
        var timeout = TimeSpan.FromMilliseconds(Math.Max(options.ConnectTimeout.TotalMilliseconds * 1.5, 1200));
        using var gate = new SemaphoreSlim(3);

        var tasks = ports.Select(async port =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var elapsed = await TryConnectAsync(address, port, timeout, ct);
                if (elapsed is { } e) lock (found) found.Add((port, e));
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks);
        return found;
    }

    private static async Task<TimeSpan?> PingAsync(IPAddress address, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, timeout).WaitAsync(ct);
            return reply.Status == IPStatus.Success ? TimeSpan.FromMilliseconds(reply.RoundtripTime) : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<TimeSpan?> TryConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            using var client = new TcpClient();
            await client.ConnectAsync(address, port, cts.Token);
            return sw.Elapsed;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException)
        {
            return null;
        }
    }

    private static async Task<HttpEvidence?> ProbeHttpAsync(IPAddress address, int port, ScanOptions options, CancellationToken token)
    {
        bool httpsFirst = options.HttpsPorts.Contains(port);
        var schemes = httpsFirst ? new[] { "https", "http" } : new[] { "http", "https" };

        // One retry covers a miner whose web server is still starting after a reboot or network change.
        for (int attempt = 0; attempt < 2; attempt++)
        {
            foreach (var scheme in schemes)
            {
                var result = await TryHttpAsync(address, port, scheme, options, token);
                if (result is not null) return result;
                if (token.IsCancellationRequested) return null;
            }

            if (attempt == 0)
            {
                try { await Task.Delay(500, token); }
                catch (OperationCanceledException) { return null; }
            }
        }

        return null;
    }

    private static async Task<HttpEvidence?> TryHttpAsync(IPAddress address, int port, string scheme, ScanOptions options, CancellationToken token)
    {
        string? certSubject = null;
        bool certTrusted = scheme == "http";

        // The probe only issues an anonymous GET / and discards the connection, so accepting
        // self-signed miner certificates here exposes nothing. The trust state is recorded.
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectTimeout = options.ConnectTimeout,
            AutomaticDecompression = DecompressionMethods.All,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                {
                    certSubject = cert?.Subject;
                    certTrusted = errors == SslPolicyErrors.None;
                    return true;
                },
            },
        };
        using var client = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        cts.CancelAfter(options.HttpTimeout);

        try
        {
            var uri = new UriBuilder(scheme, address.ToString(), port).Uri;
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.UserAgent.ParseAdd("IpScanner/1.0");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);

            string body = await ReadBodyAsync(response, options.MaxBodyBytes, cts.Token);
            string? title = null;
            var titleMatch = TitleRegex().Match(body);
            if (titleMatch.Success)
                title = Truncate(Regex.Replace(WebUtility.HtmlDecode(titleMatch.Groups[1].Value), @"\s+", " ").Trim(), 200);

            string? realm = null;
            var challenge = response.Headers.WwwAuthenticate.ToString();
            if (challenge.Length > 0)
            {
                var realmMatch = RealmRegex().Match(challenge);
                if (realmMatch.Success) realm = Truncate(realmMatch.Groups[1].Value.Trim(), 120);
            }

            return new HttpEvidence(
                port, scheme, (int)response.StatusCode, title,
                Truncate(response.Headers.Server.ToString(), 120),
                Truncate(response.Headers.Location?.OriginalString, 300),
                realm, certSubject, certTrusted, body);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or InvalidOperationException)
        {
            return null;
        }
    }

    private static async Task<string> ReadBodyAsync(HttpResponseMessage response, int maxBytes, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        var buffer = new byte[maxBytes];
        int total = 0;
        try
        {
            while (total < maxBytes)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(total, maxBytes - total), ct);
                if (read == 0) break;
                total += read;
            }
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or OperationCanceledException)
        {
            // Keep whatever arrived before a malformed or slow response failed.
        }

        return Encoding.UTF8.GetString(buffer, 0, total);
    }

    /// <summary>Sends the read-only cgminer "version" command; no state is changed on the miner.</summary>
    private static async Task<string?> ReadMinerApiAsync(IPAddress address, ScanOptions options, CancellationToken token)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(options.ApiTimeout);
            using var client = new TcpClient();
            await client.ConnectAsync(address, options.ApiPort, cts.Token);
            await using var stream = client.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes("{\"command\":\"version\"}"), cts.Token);

            var buffer = new byte[4096];
            int total = 0;
            while (total < buffer.Length)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(total), cts.Token);
                if (read == 0) break;
                total += read;
                if (Array.IndexOf(buffer, (byte)0, 0, total) >= 0) break;
            }

            string text = Encoding.UTF8.GetString(buffer, 0, total).Trim('\0', ' ', '\r', '\n');
            return text.Length == 0 ? null : Truncate(text, 1024);
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException)
        {
            return null;
        }
    }

    private static async Task<string?> ResolveHostnameAsync(IPAddress address, TimeSpan timeout, CancellationToken token)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(address.ToString(), token).WaitAsync(timeout, token);
            string name = entry.HostName;
            return string.Equals(name, address.ToString(), StringComparison.Ordinal) ? null : name;
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or TimeoutException)
        {
            return null;
        }
    }

    private static string? Truncate(string? value, int max) =>
        string.IsNullOrEmpty(value) ? null : value.Length <= max ? value : value[..max];
}
