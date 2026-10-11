using System.Net;
using System.Net.Sockets;
using System.Text;
using IpScanner.Core.Discovery;

namespace IpScanner.Core.Tests;

public class IpReportListenerTests
{
    private static readonly IPAddress Miner = IPAddress.Parse("192.168.1.55");

    [Fact]
    public void Parses_bitmain_style_report()
    {
        var r = IpReportListener.Parse(Miner, "192.168.1.55,AA:BB:CC:DD:EE:FF"u8);
        Assert.Equal(IPAddress.Parse("192.168.1.55"), r.ReportedIp);
        Assert.Equal("AA:BB:CC:DD:EE:FF", r.ReportedMac);
        Assert.Equal(IPAddress.Parse("192.168.1.55"), r.Target);
    }

    [Fact]
    public void Normalizes_dashed_lowercase_mac_and_finds_ip_in_free_text()
    {
        var r = IpReportListener.Parse(Miner, "Jasminer IP 192.168.1.99 mac de-e5-38-f4-64-87"u8);
        Assert.Equal(IPAddress.Parse("192.168.1.99"), r.ReportedIp);
        Assert.Equal("DE:E5:38:F4:64:87", r.ReportedMac);
    }

    [Fact]
    public void Falls_back_to_the_sender_when_the_payload_has_no_ip()
    {
        var r = IpReportListener.Parse(Miner, "hello"u8);
        Assert.Null(r.ReportedIp);
        Assert.Equal(Miner, r.Target);
    }

    [Fact]
    public void Ignores_public_ips_claimed_in_the_payload()
    {
        var r = IpReportListener.Parse(Miner, "8.8.8.8,AA:BB:CC:DD:EE:FF"u8);
        Assert.Null(r.ReportedIp);
        Assert.Equal(Miner, r.Target);
    }

    [Fact]
    public void Binary_and_oversized_payloads_are_rendered_safely()
    {
        var binary = IpReportListener.Parse(Miner, new byte[] { 0, 1, 2, 3, 0xff, 0xfe, 0x80, 0x01 });
        Assert.StartsWith("(binary)", binary.Text);

        var big = IpReportListener.Parse(Miner, new byte[100_000].Select(_ => (byte)'A').ToArray());
        Assert.True(big.Text.Length <= 200);
    }

    [Theory]
    [InlineData("192.168.1.5", true)]
    [InlineData("10.0.0.5", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("127.0.0.1", false)]
    public void Only_private_senders_are_accepted(string ip, bool expected) =>
        Assert.Equal(expected, IpReportListener.IsAcceptableSender(IPAddress.Parse(ip)));

    [Fact]
    public async Task Receives_a_real_udp_datagram_and_stops_on_cancel()
    {
        int port;
        using (var probe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
            port = ((IPEndPoint)probe.Client.LocalEndPoint!).Port;

        var received = new TaskCompletionSource<IpReport>();
        using var cts = new CancellationTokenSource();
        var listening = IpReportListener.ListenAsync(port, r => received.TrySetResult(r), cts.Token, allowLoopback: true);

        using var sender = new UdpClient();
        for (int i = 0; i < 20 && !received.Task.IsCompleted; i++)
        {
            await sender.SendAsync(Encoding.ASCII.GetBytes("192.168.1.77,AA:BB:CC:00:11:22"), new IPEndPoint(IPAddress.Loopback, port));
            await Task.WhenAny(received.Task, Task.Delay(100));
        }

        var report = await received.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(IPAddress.Parse("192.168.1.77"), report.ReportedIp);

        cts.Cancel();
        await listening.WaitAsync(TimeSpan.FromSeconds(3));
    }
}
