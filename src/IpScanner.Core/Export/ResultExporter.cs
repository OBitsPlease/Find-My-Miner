using System.Text;
using System.Text.Json;

namespace IpScanner.Core.Export;

public sealed record ExportRow(
    string Ip,
    string? Hostname,
    string? FriendlyName,
    string? Mac,
    string Platform,
    string? Model,
    string Confidence,
    int Score,
    string? ManagementUrl,
    string Ports,
    DateTimeOffset LastSeen);

public static class ResultExporter
{
    private static readonly string[] Headers =
        ["IP", "Hostname", "Name", "MAC", "Platform", "Model", "Confidence", "Score", "URL", "Ports", "LastSeen"];

    public static string ToCsv(IEnumerable<ExportRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', Headers));
        foreach (var r in rows)
        {
            sb.AppendLine(string.Join(',', new[]
            {
                r.Ip, r.Hostname, r.FriendlyName, r.Mac, r.Platform, r.Model, r.Confidence,
                r.Score.ToString(), r.ManagementUrl, r.Ports, r.LastSeen.ToString("O"),
            }.Select(Escape)));
        }

        return sb.ToString();
    }

    public static string ToJson(IEnumerable<ExportRow> rows) =>
        JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true });

    /// <summary>Quotes CSV fields and neutralises spreadsheet formulas, since hostnames come from the network.</summary>
    public static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }
}
