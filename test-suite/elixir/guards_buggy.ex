defmodule Inventory do
  @moduledoc """
  Deep map access with no nil guard anywhere.
  """

  def catalog_total(envelope) do
    envelope.data.metrics.count.total
  end

  def region_name(client) do
    client.conn.region.host.name
  end

  def warehouse_slug(store) do
    store.primary.warehouse.code
  end
end
