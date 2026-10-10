defmodule CallbackSqlClean do
  def direct(params) do
    execute = fn name ->
      Ecto.Adapters.SQL.query!(ApplicationRepo,
        "SELECT Id FROM Users WHERE Name = $1", [name])
    end
    execute.(params["name"])
  end

  def captured(params) do
    name = params["name"]
    execute = fn ->
      Ecto.Adapters.SQL.query!(ApplicationRepo,
        "SELECT Id FROM Users WHERE Name = $1", [name])
    end
    execute.()
  end

  def batch(params) do
    Enum.each([params["name"]], fn name ->
      Ecto.Adapters.SQL.query!(ApplicationRepo,
        "SELECT Id FROM Users WHERE Name = $1", [name])
    end)
  end
end
