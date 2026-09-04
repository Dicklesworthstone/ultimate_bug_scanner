package inventory

import "fmt"

// CatalogTotal checks the envelope before walking it (early-exit guard).
func CatalogTotal(resp *CatalogResponse) int {
	if resp == nil || resp.Catalog == nil {
		return 0
	}
	return resp.Catalog.Page.Items.Total
}

// ShipmentLabel guards every level it dereferences.
func ShipmentLabel(client *ShipClient) string {
	if client == nil || client.Conn == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s", client.Conn.Region.Host.Name, client.Conn.Region.Code)
}

// WarehouseName guards inside the condition and uses the chain in the body.
func WarehouseName(cfg *InventoryConfig) string {
	if cfg != nil && cfg.Stores != nil {
		return cfg.Stores.Primary.Warehouse.Name
	}
	return "unknown"
}

// SafeName never dereferences: it formats through the nil-safe fallback.
func SafeName(cfg *InventoryConfig) string {
	name := "unknown"
	if cfg != nil && cfg.Stores != nil && cfg.Stores.Primary != nil {
		name = cfg.Stores.Primary.Warehouse.Name
	}
	return name
}
