package com.example.inventory;

class OrderTotalClean {

    int catalogTotal(Customer customer) {
        if (customer == null || customer.profile == null) {
            return 0;
        }
        return customer.profile.stats.orders.total;
    }

    String shipmentLabel(ShipClient client) {
        if (client instanceof ShipClient) {
            return client.conn.region.host.name;
        }
        return "";
    }

    int safeTotal(Customer customer) {
        return customer != null ? customer.profile.stats.orders.total : 0;
    }

    int requiredTotal(Customer customer) {
        Objects.requireNonNull(customer, "customer");
        if (Objects.isNull(customer.profile)) {
            return 0;
        }
        return customer.profile.stats.orders.total;
    }
}
