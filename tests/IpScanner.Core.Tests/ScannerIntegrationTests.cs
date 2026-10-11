using System.Net;
using System.Net.Sockets;
using System.Text;
using IpScanner.Core.Detection;
using IpScanner.Core.Discovery;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Tests;

/// <summary>Tiny loopback TCP server used to emulate a miner's web UI and API.</summary>
internal sealed class MockServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();

    public MockServer(Func<NetworkStream, CancellationToken, Task> handler, int port = 0)
    {
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            try { await handler(client.GetStream(), _cts.Token); }
                            catch (Exception) { }
                        }
                    });
                }
            }
            catch (OperationCanceledException) { }
        });
    }

    public int Port { get; }

    public static MockServer Http(string html, int status = 200, string extraHeaders = "", int port = 0) =>
        new(async (stream, ct) =>
        {
            var buffer = new byte[2048];
            await stream.ReadAtLeastAsync(buffer, 1, false, ct);
            byte[] body = Encoding.UTF8.GetBytes(html);
            string head = $"HTTP/1.1 {status} OK\r\nContent-Type: text/html\r\nContent-Length: {body.Length}\r\n{extraHeaders}Connection: close\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(head), ct);
            await stream.WriteAsync(body, ct);
        }, port);

    public static MockServer Api(string json) =>
        new(async (stream, ct) =>
        {
            var buffer = new byte[256];
            await stream.ReadAtLeastAsync(buffer, 1, false, ct);
            await stream.WriteAsync(Encoding.UTF8.GetBytes(json + "\0"), ct);
        });

    public static MockServer Hang() =>
        new(async (stream, ct) => await Task.Delay(Timeout.Infinite, ct));

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
    }
}

public class ScannerIntegrationTests
{
    private static readonly Subnet Loopback = new(IPAddress.Loopback, 32);

    private static ScanOptions Options(int[] ports, int[] webPorts, int apiPort = 4028) => new()
    {
        Ports = ports,
        WebPorts = webPorts,
        HttpsPorts = [],
        ApiPort = apiPort,
        AllowLoopback = true,
        ConnectTimeout = TimeSpan.FromMilliseconds(500),
        HttpTimeout = TimeSpan.FromSeconds(2),
        ApiTimeout = TimeSpan.FromSeconds(1),
        DnsTimeout = TimeSpan.FromMilliseconds(300),
    };

    private static NetworkScanner Scanner() => new(new HostProber(), new MinerDetector());

    [Fact]
    public async Task Finds_and_identifies_a_miner_by_http_and_api()
    {
        using var web = MockServer.Http("<html><head><title>JASMINER X4-Q Login</title></head><body>Sign in</body></html>");
        using var api = MockServer.Api("{\"STATUS\":[{\"STATUS\":\"S\"}],\"VERSION\":[{\"CGMiner\":\"4.11.1\",\"API\":\"3.7\"}]}");

        var found = new List<DeviceResult>();
        await Scanner().ScanAsync(Loopback, Options([web.Port, api.Port], [web.Port], api.Port),
            new ScanCallbacks { OnDevice = d => { lock (found) found.Add(d); } }, false, CancellationToken.None);

        var device = Assert.Single(found);
        Assert.Equal(BuiltInFingerprints.Jasminer, device.Detection.Platform);
        Assert.Equal("X4-Q", device.Detection.Model);
        Assert.Contains("CGMiner", device.Evidence.ApiBanner);
        Assert.Equal($"http://127.0.0.1:{web.Port}/", device.ManagementUrl);
        Assert.Equal("JASMINER X4-Q Login", device.Evidence.Http[0].Title);
    }

    [Fact]
    public async Task Discovers_hosts_that_only_answer_tcp()
    {
        using var api = MockServer.Api("{}");
        var found = new List<DeviceResult>();
        await Scanner().ScanAsync(Loopback, Options([api.Port], [], api.Port),
            new ScanCallbacks { OnDevice = found.Add }, false, CancellationToken.None);
        Assert.Single(found);
        Assert.Contains(api.Port, found[0].Evidence.OpenPorts);
    }

    [Fact]
    public async Task Reports_a_miss_for_closed_hosts_and_progress()
    {
        var missed = new List<IPAddress>();
        int lastScanned = 0;
        var options = Options([1], []) with { PingTimeout = TimeSpan.FromMilliseconds(100) };
        // 127.0.0.1 answers ping, so use a closed-port-only probe against a stub that sees no host.
        var scanner = new NetworkScanner(new NullProber(), new MinerDetector());
        await scanner.ScanAsync(Loopback, options,
            new ScanCallbacks { OnMiss = missed.Add, OnProgress = (s, _) => lastScanned = s }, false, CancellationToken.None);
        Assert.Single(missed);
        Assert.Equal(1, lastScanned);
    }

    [Fact]
    public async Task Limits_the_body_read_size()
    {
        using var web = MockServer.Http("<title>big</title>" + new string('x', 200_000));
        var found = new List<DeviceResult>();
        await Scanner().ScanAsync(Loopback, Options([web.Port], [web.Port]) with { MaxBodyBytes = 4096 },
            new ScanCallbacks { OnDevice = found.Add }, false, CancellationToken.None);
        Assert.True(found[0].Evidence.Http[0].BodySnippet.Length <= 4096);
    }

    [Fact]
    public async Task Survives_a_malformed_web_server()
    {
        using var broken = new MockServer(async (stream, ct) =>
        {
            await stream.ReadAtLeastAsync(new byte[1024], 1, false, ct);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("this is not http\r\n\r\n"), ct);
        });
        var found = new List<DeviceResult>();
        await Scanner().ScanAsync(Loopback, Options([broken.Port], [broken.Port]),
            new ScanCallbacks { OnDevice = found.Add }, false, CancellationToken.None);
        var device = Assert.Single(found);
        Assert.Empty(device.Evidence.Http);
        Assert.Null(device.ManagementUrl);
    }

    [Fact]
    public async Task Hung_services_time_out_instead_of_blocking()
    {
        using var hang = MockServer.Hang();
        var options = Options([hang.Port], [hang.Port]) with { HttpTimeout = TimeSpan.FromMilliseconds(600) };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var found = new List<DeviceResult>();
        await Scanner().ScanAsync(Loopback, options, new ScanCallbacks { OnDevice = found.Add }, false, CancellationToken.None);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(8), $"took {sw.Elapsed}");
        Assert.Single(found);
    }

    [Fact]
    public async Task Recovers_ports_a_device_dropped_during_the_first_burst()
    {
        // Reserve a port, leave it closed for the first pass, then bring the "device" up shortly after.
        int port;
        using (var reserve = new TcpListener(IPAddress.Loopback, 0))
        {
            reserve.Start();
            port = ((IPEndPoint)reserve.LocalEndpoint).Port;
        }

        var options = Options([port], [port]) with { PingTimeout = TimeSpan.FromMilliseconds(500) };
        var probe = new HostProber().ProbeAsync(IPAddress.Loopback, options, CancellationToken.None);

        await Task.Delay(150);
        using var late = MockServer.Http("<title>JASMINER X4 Login</title>", port: port);

        var evidence = await probe.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.NotNull(evidence);
        Assert.Contains(port, evidence!.OpenPorts);
        Assert.Equal("JASMINER X4 Login", Assert.Single(evidence.Http).Title);
    }

    [Fact]
    public async Task Cancellation_stops_the_scan_promptly()
    {
        using var hang = MockServer.Hang();
        using var cts = new CancellationTokenSource();
        var options = Options([hang.Port], [hang.Port]) with { HttpTimeout = TimeSpan.FromSeconds(30) };
        var task = Scanner().ScanAsync(Loopback, options, new ScanCallbacks(), false, cts.Token);
        await Task.Delay(300);
        cts.Cancel();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3), $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task Enforces_the_concurrency_limit()
    {
        int current = 0, peak = 0;
        var prober = new CountingProber(() =>
        {
            int now = Interlocked.Increment(ref current);
            int seen;
            while (now > (seen = Volatile.Read(ref peak)) && Interlocked.CompareExchange(ref peak, now, seen) != seen) { }
        }, () => Interlocked.Decrement(ref current));

        var options = new ScanOptions { MaxConcurrentHosts = 4 };
        await new NetworkScanner(prober, new MinerDetector())
            .ScanAsync(new Subnet(IPAddress.Parse("192.168.1.0"), 24), options, new ScanCallbacks(), false, CancellationToken.None);
        Assert.InRange(peak, 1, 4);
    }

    [Fact]
    public async Task Refuses_public_and_oversized_networks()
    {
        var scanner = new NetworkScanner(new NullProber(), new MinerDetector());
        await Assert.ThrowsAsync<ScanRejectedException>(() => scanner.ScanAsync(
            new Subnet(IPAddress.Parse("8.8.8.0"), 24), new ScanOptions(), new ScanCallbacks(), true, CancellationToken.None));
        await Assert.ThrowsAsync<ScanRejectedException>(() => scanner.ScanAsync(
            new Subnet(IPAddress.Parse("10.0.0.0"), 23), new ScanOptions(), new ScanCallbacks(), false, CancellationToken.None));
        await Assert.ThrowsAsync<ScanRejectedException>(() => scanner.ScanHostsAsync(
            [IPAddress.Parse("1.1.1.1")], new ScanOptions(), new ScanCallbacks(), CancellationToken.None));
    }

    private sealed class NullProber : IHostProber
    {
        public Task<ProbeEvidence?> ProbeAsync(IPAddress address, ScanOptions options, CancellationToken ct) =>
            Task.FromResult<ProbeEvidence?>(null);
    }

    private sealed class CountingProber(Action enter, Action exit) : IHostProber
    {
        public async Task<ProbeEvidence?> ProbeAsync(IPAddress address, ScanOptions options, CancellationToken ct)
        {
            enter();
            try { await Task.Delay(15, ct); return null; }
            finally { exit(); }
        }
    }
}
