using System.Net;
using System.Net.Sockets;
using IpScanner.Core.Networking;

namespace IpScanner.Core.Tests;

public class UdpPortOwnerTests
{
    [Fact]
    public void Finds_this_process_as_the_owner_of_a_bound_udp_port()
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        int port = ((IPEndPoint)socket.Client.LocalEndPoint!).Port;

        var owner = UdpPortOwner.TryGetOwner(port);

        Assert.NotNull(owner);
        Assert.Equal(Environment.ProcessId, owner!.Value.Pid);
    }

    [Fact]
    public void Returns_null_for_an_unused_port()
    {
        int port;
        using (var probe = new UdpClient(new IPEndPoint(IPAddress.Any, 0)))
            port = ((IPEndPoint)probe.Client.LocalEndPoint!).Port;

        Assert.Null(UdpPortOwner.TryGetOwner(port));
    }
}
