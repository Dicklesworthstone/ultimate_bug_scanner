defmodule CleanNarrowing do
  # The nil clause halts, so afterwards the value is guaranteed non-nil.
  def display_name(user) do
    case user do
      nil -> raise ArgumentError, "user required"
      _ -> :ok
    end

    user.name
  end

  # `if is_nil(value)` with a halting then-branch.
  def email_domain(user) do
    if is_nil(user) do
      raise ArgumentError, "user required"
    else
      :ok
    end

    String.split(user.email, "@")
  end

  # The guarded value is rebound to a non-nil fallback before first use.
  def handle_order(raw_order) do
    case raw_order do
      nil -> ""
      _ -> :ok
    end

    order = raw_order || fetch_default_order()
    order.id
  end

  # A partial guard is fine when the guarded value is never dereferenced.
  def log_missing(user) do
    case user do
      nil -> IO.puts("missing user")
      _ -> :ok
    end

    :ok
  end

  # The nil clause throws, which also halts the nil path.
  def shipping_label(order) do
    case order do
      nil -> throw({:error, :missing_order})
      %{} -> :ok
    end

    order.address.street
  end
end
