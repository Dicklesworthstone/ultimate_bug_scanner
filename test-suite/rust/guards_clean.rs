pub fn catalog_total(config: Option<&Config>) -> u64 {
    let Some(config) = config else {
        return 0;
    };
    config.runtime.limits.teams.max
}

pub fn catalog_total_if_let(config: Option<&Config>) -> u64 {
    if let Some(config) = config {
        return config.runtime.limits.teams.max;
    }
    0
}

pub fn shipment_region(client: Option<&Client>) -> String {
    match client {
        Some(client) => client.conn.region.host.name.clone(),
        None => String::new(),
    }
}

pub fn warehouse_slug(store: Option<&Store>) -> String {
    match store {
        Some(store) if store.primary.warehouse.code.is_empty() => String::new(),
        Some(store) => store.primary.warehouse.code.to_lowercase(),
        None => String::new(),
    }
}
