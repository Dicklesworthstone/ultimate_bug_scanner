defmodule CallbackSqlBuggy do
  def direct(params) do
    execute = fn sql ->
      Ecto.Adapters.SQL.query!(ApplicationRepo, sql, [])
    end
    execute.(params["sql"])
  end

  def captured(params) do
    sql = params["sql"]
    execute = fn ->
      Ecto.Adapters.SQL.query!(ApplicationRepo, sql, [])
    end
    execute.()
  end

  def batch(params) do
    Enum.each([params["sql"]], fn sql ->
      Ecto.Adapters.SQL.query!(ApplicationRepo, sql, [])
    end)
  end
end
