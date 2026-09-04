# GH #91 suppression fixture (bead A7) for the Elixir module, twin of
# suppression_buggy.ex (identical buggy code, no markers). Scanning this file
# must reproduce every finding the markered twin suppresses.
defmodule SuppressionBuggyNomarkers do
  import Plug.Conn
  import Phoenix.Controller

  # Arrangement 1 twin -- trailing marker position: request-derived path
  # reaches a File.read! sink (path traversal check).
  def read_download(conn) do
    name = conn.params["file"]
    path = "/srv/app/files/" <> name
    File.read!(path)
  end

  # Arrangement 2 twin -- previous-line marker position: request_path
  # concatenated into a send_file sink (path traversal check).
  def send_asset(conn) do
    requested_path = conn.request_path
    send_file(conn, 200, "/srv/app/files" <> requested_path)
  end

  # Arrangement 3 twin -- marker position inside a multi-line statement:
  # File.rm! opens a paren spanning the marker line and the Path.join
  # continuation (path traversal check).
  def delete_export(conn) do
    base = Path.expand("/srv/app/exports")
    File.rm!(
      Path.join(base, conn.params["delete"])
    )
  end

  # Arrangement 4 twin -- formatter-relocated marker position: the flagged
  # statement is the `if File.exists?(...) do` block opener and the marker
  # sits on the first line inside the block; it is also the previous line of
  # the File.rm! finding below it. The blank line after the def mirrors the
  # markered twin.
  def maybe_delete(conn) do

    if File.exists?("/srv/app/exports/" <> conn.params["delete"]) do
      File.rm!("/srv/app/exports/" <> conn.params["delete"])
    end
  end

  # Arrangement 5 twin -- rule-scoped marker position above the finding:
  # conn.host folded into an external redirect (open redirect check).
  def redirect_host(conn) do
    target = "https://" <> conn.host <> "/dashboard"
    redirect(conn, external: target)
  end

  # Arrangement 1b twin -- trailing marker position: request-derived location
  # header sink (open redirect check, put_resp_header family).
  def redirect_location_header(conn) do
    location = conn.params["location"]

    conn
    |> put_resp_header("location", location)
    |> send_resp(302, "")
  end
end
