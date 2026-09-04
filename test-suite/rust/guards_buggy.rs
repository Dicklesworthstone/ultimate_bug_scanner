pub fn catalog_total(config: &Config) -> u64 {
    config.runtime.limits.teams.max
}

pub fn shipment_region(client: &Client) -> String {
    client.conn.region.host.name.clone()
}

pub fn warehouse_slug(store: &Store) -> String {
    store.primary.warehouse.code.to_lowercase()
}
