using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace IpScanner.App.Services;

public enum ElevatedOutcome { Succeeded, Cancelled, Failed }

public sealed record ElevatedResult(ElevatedOutcome Outcome, string Message);

/// <summary>
/// Runs a script as administrator after a normal Windows permission (UAC) prompt. The script travels as an
/// encoded command rather than a file, so nothing on disk can be swapped between approval and execution.
/// </summary>
public static class ElevatedPowerShell
{
    private const int ErrorCancelled = 1223;

    public static string NewWorkDirectory()
    {
        string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "IpScanner", "work", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static async Task<ElevatedResult> RunAsync(string script, string statusFile, TimeSpan timeout, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return new(ElevatedOutcome.Failed, "This recovery operation requires Windows PowerShell and Windows Packet Monitor.");

        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
        };

        Process? process;
        try
        {
            process = Process.Start(startInfo);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            return new(ElevatedOutcome.Cancelled, "Permission was not granted.");
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            return new(ElevatedOutcome.Failed, ex.Message);
        }

        if (process is null) return new(ElevatedOutcome.Failed, "The elevated process could not be started.");

        using (process)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                return new(ElevatedOutcome.Failed, ct.IsCancellationRequested ? "Cancelled." : "The operation timed out.");
            }
        }

        string status = File.Exists(statusFile) ? (await File.ReadAllTextAsync(statusFile, CancellationToken.None)).Trim() : string.Empty;
        return status == "ok"
            ? new(ElevatedOutcome.Succeeded, string.Empty)
            : new(ElevatedOutcome.Failed, status.Length > 0 ? status : "The operation did not report a result.");
    }

    public static void TryDelete(string directory)
    {
        try { Directory.Delete(directory, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
