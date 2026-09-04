import Foundation

// CatalogTotal binds the optional before reading it (guard let).
func catalogTotal(_ envelope: Envelope?) -> Int {
    guard let envelope = envelope, envelope.isValid else {
        return 0
    }
    return envelope.data.metrics.count.total
}

// HostName guards the client then reads the chain.
func hostName(_ client: ShipClient?) -> String {
    if client == nil {
        return ""
    }
    return client.conn.region.host.name
}

// RawLabel binds with if let.
func rawLabel(_ envelope: Envelope?) -> Int {
    if let env = envelope {
        return env.data.metrics.count.total
    }
    return 0
}

// SafeName uses optional chaining end-to-end, never force-unwrapping.
func safeName(_ envelope: Envelope?) -> Int {
    return envelope?.data?.metrics?.count?.total ?? 0
}
