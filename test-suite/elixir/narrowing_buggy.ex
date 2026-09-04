defmodule BuggyNarrowing do
  # `case value do nil -> ...` whose nil clause does not halt, then the
  # guarded value is dereferenced afterwards.
  def display_name(user) do
    case user do
      nil -> ""
      _ -> :ok
    end

    user.name
  end

  # `if is_nil(value)` block form with a non-halting then-branch.
  def email_domain(user) do
    if is_nil(user) do
      IO.puts("missing user")
    end

    String.split(user.email, "@")
  end

  # `if is_nil(value)` keyword form with a non-halting then-branch.
  def handle_order(order) do
    if is_nil(order), do: IO.puts("missing order")

    order.id
  end

  # The nil clause does not halt and the value is still in scope in the
  # next function statement.
  def shipping_label(order) do
    case order do
      nil -> ""
      %{} -> :ok
    end

    dest = order.address
    "#{dest.street} #{dest.city}"
  end
end
