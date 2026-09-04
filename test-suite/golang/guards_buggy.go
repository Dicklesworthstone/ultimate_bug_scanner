package inventory

import "fmt"

// CatalogTotal walks the response envelope without any nil check.
func CatalogTotal(resp *CatalogResponse) int {
	return resp.Catalog.Page.Items.Total
}

// ShipmentLabel builds a label straight off the client result.
func ShipmentLabel(client *ShipClient) string {
	return fmt.Sprintf("%s/%s", client.Conn.Region.Host.Name, client.Conn.Region.Code)
}

// WarehouseName dereferences the store chain with no guard.
func WarehouseName(cfg *InventoryConfig) string {
	return cfg.Stores.Primary.Warehouse.Name
}
