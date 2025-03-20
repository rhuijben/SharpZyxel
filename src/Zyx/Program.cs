using SharpZyxel;
using System.Diagnostics.CodeAnalysis;

namespace Zyx;

internal class Program
{
    static async Task<int> Main(string[] args)
    {
        var arg = args.LastOrDefault();

        switch (arg?.ToLower())
        {
            case "ls":
            case null:
                await ListAsync(args);
                return 0;

            default:
                Console.Error.WriteLine("Usage zyz ls");
                return 1;
        }
    }

    static readonly Dictionary<string, string> HostTable = new()
    {
        ["EX5601-T1"] = "GW-Beneden",
        ["WX5600-AP-37096"] = "AP-Tussen",
        ["WX5600-AP-09535"] = "AP-Zolder",
    };

    private static async Task ListAsync(string[] args)
    {
        using var zx = new ZyxelClient();


        foreach (var lh in (await zx.GetLanHostsAsync())
            .Where(x => x.Active == true)
            .OrderBy(x => string.Join('.', x.IPAddress?.Split('.').Select(x => x.PadLeft(3, '0')) ?? [])))
        {
            Console.Write((lh.IPAddress?.TrimToNull() ?? lh.IPAddress6?.TrimToNull() ?? "").PadRight(13));

            Console.Write(" ");

            Console.Write((lh.curHostName?.TrimToNull() ?? lh.HostName?.TrimToNull() ?? lh.DeviceName?.TrimToNull() ?? "").PadRight(20));
            Console.Write(" ");

            Console.Write((lh.PhysAddress ?? "").PadRight(17));
            Console.Write(" ");

            Console.Write((lh.X_ZYXEL_Neighbor.Translate(HostTable)?.TrimToNull() ?? "").PadRight(12));

            if (lh.X_ZYXEL_HostType?.Contains("Wifi", StringComparison.OrdinalIgnoreCase) == true)
            {
                Console.Write($"{lh.X_ZYXEL_ConnectionType}-{lh.X_ZYXEL_OperatingStandard} {MakeRate(lh)}");
            }
            else
            {
                Console.Write($"Ethernet");
            }



            Console.WriteLine();
        }
    }

    private static string? MakeRate(ZyxelClient.LanHost lh)
    {
        if (lh.X_ZYXEL_LastDataDownlinkRate is { } && lh.X_ZYXEL_LastDataUplinkRate is { })
        {
            return $"{decimal.Round(lh.X_ZYXEL_LastDataUplinkRate.Value / 1000, 0)}/{decimal.Round(lh.X_ZYXEL_LastDataDownlinkRate.Value / 1000, 0)} MBit";
        }
        else if (lh.X_ZYXEL_PhyRate is { } pr)
            return $"{pr} MBit";
        else
            return null;
    }
}

static class Extensions
{
    public static string? TrimToNull(this string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        else
            return value.Trim();
    }

    [return: NotNullIfNotNull(nameof(value))]
    public static string? Translate(this string? value, Dictionary<string, string>? translations)
    {
        if (!string.IsNullOrWhiteSpace(value)
            && translations?.TryGetValue(value, out var v) == true)
        {
            return v;
        }

        return value;
    }
}
