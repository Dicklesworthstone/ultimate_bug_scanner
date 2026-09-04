import Foundation

// CatalogTotal walks the envelope with no optional binding.
func catalogTotal(_ envelope: Envelope) -> Int {
    return envelope.data.metrics.count.total
}

// HostName forces the unwrap chain with no guard.
func hostName(_ client: ShipClient) -> String {
    return client.conn.region.host.name
}

// RawLabel reads through the optional without `if let` / `guard`.
func rawLabel(_ envelope: Envelope?) -> Int {
    return envelope!.data.metrics.count.total
}
