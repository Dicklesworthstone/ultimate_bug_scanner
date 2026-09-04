defmodule InventoryClean do
  @moduledoc """
  Every deep access sits behind an explicit nil guard.
  """

  def catalog_total(envelope) do
    case envelope do
      nil -> 0
      _ -> envelope.data.metrics.count.total
    end
  end

  def region_name(client) do
    if is_nil(client) do
      ""
    else
      client.conn.region.host.name
    end
  end

  def warehouse_slug(store) do
    unless is_nil(store) do
      store.primary.warehouse.code
    end
  end

  def region_name_with(client) do
    with {:ok, region} <- Map.fetch(client || %{}, :region) do
      region.host.name
    end
  end
end
