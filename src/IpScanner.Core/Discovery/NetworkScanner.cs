using System.Net;
using IpScanner.Core.Detection;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Discovery;

/// <summary>Runs bounded-concurrency probes across a subnet and streams results back.</summary>
public sealed class NetworkScanner(IHostProber prober, MinerDetector detector)
{
    public Task ScanAsync(
        Subnet subnet,
        ScanOptions options,
        ScanCallbacks callbacks,
        bool confirmedLargeNetwork,
        CancellationToken cancellationToken)
    {
        options = options.Normalized();
        var guard = ScanGuard.Check(subnet, options);
        if (guard.Verdict == GuardVerdict.Rejected ||
            (guard.Verdict == GuardVerdict.NeedsConfirmation && !confirmedLargeNetwork))
            throw new ScanRejectedException(guard.Message);

        return ScanHostsAsync(subnet.EnumerateHosts().ToList(), options, callbacks, cancellationToken);
    }

    /// <summary>
    /// Finds devices on the adapter's link that have no IPv4 address (or were not found over IPv4)
    /// and probes them over IPv6. MACs already seen over IPv4 are skipped.
    /// </summary>
    public async Task ScanIpv6Async(
        NetworkAdapterInfo adapter,
        IReadOnlySet<string> macsAlreadyFound,
        ScanOptions options,
        ScanCallbacks callbacks,
        CancellationToken cancellationToken)
    {
        options = options.Normalized();
        var targets = (await Ipv6Discovery.DiscoverAsync(adapter, cancellationToken))
            .Where(n => !macsAlreadyFound.Contains(n.Mac))
            .Take(options.MaxHosts)
            .ToList();

        await Parallel.ForEachAsync(
            targets,
            new ParallelOptions { MaxDegreeOfParallelism = options.MaxConcurrentHosts, CancellationToken = cancellationToken },
            async (neighbor, ct) =>
            {
                try
                {
                    var evidence = await prober.ProbeAsync(neighbor.Address, options, ct);
                    if (evidence is null) return;
                    var detection = detector.Detect(evidence);
                    callbacks.OnDevice?.Invoke(new DeviceResult(evidence, detection, UrlSelector.Choose(evidence, detection.MatchedPort)));
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception)
                {
                    // An unreachable IPv6 neighbor is simply skipped.
                }
            });
    }

    /// <summary>Probes specific hosts (used for rescans). Every host must be on a private network.</summary>
    public async Task ScanHostsAsync(
        IReadOnlyList<IPAddress> hosts,
        ScanOptions options,
        ScanCallbacks callbacks,
        CancellationToken cancellationToken)
    {
        options = options.Normalized();
        if (hosts.Count > options.MaxHosts)
            throw new ScanRejectedException($"Too many hosts ({hosts.Count:N0}); the limit is {options.MaxHosts:N0}.");
        if (hosts.FirstOrDefault(h => !ScanGuard.IsAllowedHost(h, options)) is { } blocked)
            throw new ScanRejectedException($"{blocked} is not a private address and will not be scanned.");

        int scanned = 0;
        int total = hosts.Count;

        await Parallel.ForEachAsync(
            hosts,
            new ParallelOptions { MaxDegreeOfParallelism = options.MaxConcurrentHosts, CancellationToken = cancellationToken },
            async (host, ct) =>
            {
                try
                {
                    var evidence = await prober.ProbeAsync(host, options, ct);
                    if (evidence is null)
                    {
                        callbacks.OnMiss?.Invoke(host);
                    }
                    else
                    {
                        var detection = detector.Detect(evidence);
                        callbacks.OnDevice?.Invoke(new DeviceResult(evidence, detection, UrlSelector.Choose(evidence, detection.MatchedPort)));
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception)
                {
                    // One misbehaving host must never abort the whole scan.
                    callbacks.OnMiss?.Invoke(host);
                }
                finally
                {
                    callbacks.OnProgress?.Invoke(Interlocked.Increment(ref scanned), total);
                }
            });
    }
}
