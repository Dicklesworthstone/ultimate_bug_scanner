namespace Inventory.Telemetry;

class Telemetry
{
    public int TimeoutMs(Config cfg)
    {
        return cfg.Http.Stack.Retry.TimeoutMs;
    }

    public string Region(ShipClient client)
    {
        return client.Conn.Region.Host.Name;
    }

    public int RawFallback(Config cfg)
    {
        // ?? coalescing alone never checks the chain it reads
        return cfg.Http.Stack.Retry.TimeoutMs + (cfg.RetryLimit ?? 0);
    }
}
