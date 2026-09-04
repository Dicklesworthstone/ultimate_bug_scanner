#include <string>

// CatalogTotal checks the pointer before dereferencing (early exit).
int catalog_total(Envelope* envelope) {
    if (envelope == nullptr) {
        return 0;
    }
    return envelope->data.metrics.count.total;
}

// RegionName guards the client, then reads the chain.
std::string region_name(ShipClient* client) {
    if (client == NULL) {
        return "";
    }
    return client->conn.region.host.name;
}

// ZoomLevel uses the truthiness idiom.
int zoom_level(World* world) {
    if (!world) {
        return -1;
    }
    return world->map.zoom.level.max;
}

// TernaryFallback picks the guarded branch with ?:.
int ternary_fallback(Envelope* envelope) {
    return envelope != nullptr ? envelope->data.metrics.count.total : 0;
}
