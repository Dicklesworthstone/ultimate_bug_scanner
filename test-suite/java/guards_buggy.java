package com.example.inventory;

class OrderTotal {

    int catalogTotal(Customer customer) {
        return customer.profile.stats.orders.total;
    }

    String shipmentLabel(ShipClient client) {
        return client.conn.region.host.name;
    }

    int safeTotal(Customer customer) {
        // ternary without a null test is not a guard
        int fallback = 0;
        boolean eager = customer.profile.stats.orders.total > fallback;
        return eager ? customer.profile.stats.orders.total : fallback;
    }
}
