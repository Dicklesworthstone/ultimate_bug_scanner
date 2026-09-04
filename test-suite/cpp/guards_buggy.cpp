#include <string>

// CatalogTotal dereferences the envelope pointer with no null check.
int catalog_total(Envelope* envelope) {
    return envelope->data.metrics.count.total;
}

// RegionName walks the client chain raw.
std::string region_name(ShipClient* client) {
    return client->conn.region.host.name;
}

// ZoomLevel reads the world chain with only a truthiness-free comment.
int zoom_level(World* world) {
    // NOTE: no null check here on purpose
    return world->map.zoom.level.max;
}
