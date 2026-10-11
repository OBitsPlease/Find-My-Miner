using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Discovery;

public sealed record IpReport(
    DateTimeOffset ReceivedAt,
    IPAddress Sender,
    string Text,
    IPAddress? ReportedIp,
    string? ReportedMac)
{
    /// <summary>The address to open: the miner's own claim when valid, otherwise the packet's source.</summary>
    public IPAddress Target => ReportedIp ?? Sender;
}

/// <summary>
/// Passively listens for the UDP broadcast many miners send when their "IP report" button is pressed
/// (Bitmain-style tools use UDP 14235). It only receives; nothing is sent.
/// </summary>
public static partial class IpReportListener
{
    public const int DefaultPort = 14235;
    private const int MaxTextLength = 200;

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.None, matchTimeoutMilliseconds: 250)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b", RegexOptions.None, matchTimeoutMilliseconds: 250)]
    private static partial Regex MacRegex();

    /// <summary>Only packets from private-network hosts are accepted (loopback only for tests).</summary>
    public static bool IsAcceptableSender(IPAddress sender, bool allowLoopback = false) =>
        Subnet.IsPrivate(sender) || (allowLoopback && IPAddress.IsLoopback(sender));

    /// <summary>Turns an untrusted datagram into a safe, displayable report.</summary>
    public static IpReport Parse(IPAddress sender, ReadOnlySpan<byte> data, DateTimeOffset? receivedAt = null)
    {
        var slice = data[..Math.Min(data.Length, MaxTextLength)];
        int unprintable = 0;
        foreach (byte b in slice)
            if (b is < 0x20 and not (byte)'\t' || b > 0x7e) unprintable++;

        string text = slice.Length > 0 && unprintable * 10 > slice.Length * 3
            ? "(binary) " + Convert.ToHexString(slice[..Math.Min(slice.Length, 48)])
            : new string(Encoding.ASCII.GetString(slice).Select(c => c is < ' ' or > '~' ? ' ' : c).ToArray()).Trim();

        IPAddress? reportedIp = null;
        string? mac = null;
        try
        {
            foreach (Match m in Ipv4Regex().Matches(text))
            {
                if (IPAddress.TryParse(m.Value, out var ip) && Subnet.IsPrivate(ip))
                {
                    reportedIp = ip;
                    break;
                }
            }

            var macMatch = MacRegex().Match(text);
            if (macMatch.Success) mac = macMatch.Value.Replace('-', ':').ToUpperInvariant();
        }
        catch (RegexMatchTimeoutException)
        {
        }

        return new IpReport(receivedAt ?? DateTimeOffset.Now, sender, text, reportedIp, mac);
    }

    /// <summary>Listens until cancelled, invoking <paramref name="onReport"/> for each acceptable datagram.</summary>
    public static async Task ListenAsync(int port, Action<IpReport> onReport, CancellationToken cancellationToken, bool allowLoopback = false)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));

        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        client.Client.Bind(new IPEndPoint(IPAddress.Any, port));

        try
        {
            while (true)
            {
                var result = await client.ReceiveAsync(cancellationToken);
                if (!IsAcceptableSender(result.RemoteEndPoint.Address, allowLoopback)) continue;
                onReport(Parse(result.RemoteEndPoint.Address, result.Buffer));
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }
}
