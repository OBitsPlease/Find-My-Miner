using System.Net;
using IpScanner.Core.Networking;
using IpScanner.Core.Settings;

namespace IpScanner.App.Services;

/// <summary>Removes temporary addresses that Find My Miner added, using administrator permission.</summary>
public static class TemporaryAddressService
{
    public static async Task<ElevatedResult> RemoveAllAsync(AppSettings settings)
    {
        var items = settings.TemporaryAddresses
            .Select(r => (r.InterfaceIndex, Parsed: IPAddress.TryParse(r.Address, out var ip) ? ip : null))
            .Where(x => x.Parsed is not null)
            .Select(x => (x.InterfaceIndex, x.Parsed!))
            .ToList();

        if (items.Count == 0)
        {
            settings.TemporaryAddresses.Clear();
            return new(ElevatedOutcome.Succeeded, string.Empty);
        }

        string dir = ElevatedPowerShell.NewWorkDirectory();
        try
        {
            string status = System.IO.Path.Combine(dir, OffSubnetDiscovery.StatusFileName);
            var result = await ElevatedPowerShell.RunAsync(
                TemporaryAddress.BuildRemoveScript(items, status), status, TimeSpan.FromSeconds(90), CancellationToken.None);

            if (result.Outcome == ElevatedOutcome.Succeeded) settings.TemporaryAddresses.Clear();
            return result;
        }
        finally
        {
            ElevatedPowerShell.TryDelete(dir);
        }
    }
}
