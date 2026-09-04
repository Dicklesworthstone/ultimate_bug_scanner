using System;
using Inventory.Config;

namespace Inventory.Telemetry.Clean
{
    public class TelemetryClean
    {
        public int TimeoutMs(Config cfg)
        {
            if (cfg is null)
            {
                return 0;
            }
            return cfg.Http.Stack.Retry.TimeoutMs;
        }

        public string Region(ShipClient client)
        {
            if (!string.IsNullOrEmpty(client?.Conn?.Region?.Host?.Name))
            {
                return client.Conn.Region.Host.Name;
            }
            return "";
        }

        public int SafeFallback(Config cfg)
        {
            return cfg?.Http?.Stack?.Retry?.TimeoutMs ?? 0;
        }

        public int CheckedCoalesce(Config cfg)
        {
            if (cfg is not null && cfg.Http is not null)
            {
                return cfg.Http.Stack.Retry.TimeoutMs + (cfg.RetryLimit ?? 0);
            }
            return 0;
        }
    }
}
