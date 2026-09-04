# GH #91 suppression fixture (bead A7) for the Elixir module, twin of
# suppression_buggy_nomarkers.ex (identical buggy code, no markers).
#
# Every native elixir finding below (the path:line code samples the module
# prints for the request-derived path-traversal and open-redirect checks)
# carries a marker comment in one of the four honored arrangements:
#   1. trailing the flagged line,
#   2. on the line immediately above the flagged statement,
#   3. on a physical line inside a multi-line statement,
#   4. formatter-relocated: on the first line inside a `do` block that the
#      flagged statement opens (mix format pushes block-attached trailing
#      comments inside).
# plus rule-scoped variants (rule id in square brackets). Scanning this file
# must report zero surviving findings, while the nomarkers twin reproduces
# them.
defmodule SuppressionBuggy do
  import Plug.Conn
  import Phoenix.Controller

  # ---------------------------------------------------------------------------
  # Arrangement 1 -- trailing marker, rule-scoped: request-derived path reaches
  # a File.read! sink (path traversal check).
  # ---------------------------------------------------------------------------
  def read_download(conn) do
    name = conn.params["file"]
    path = "/srv/app/files/" <> name
    File.read!(path) # ubs:ignore[ex.request-path-traversal] -- trailing rule-scoped marker
  end

  # ---------------------------------------------------------------------------
  # Arrangement 2 -- previous-line marker: request_path concatenated into a
  # send_file sink (path traversal check).
  # ---------------------------------------------------------------------------
  def send_asset(conn) do
    requested_path = conn.request_path
    # ubs:ignore -- previous-line marker arrangement
    send_file(conn, 200, "/srv/app/files" <> requested_path)
  end

  # ---------------------------------------------------------------------------
  # Arrangement 3 -- marker on a physical line inside a multi-line statement:
  # File.rm! opens a paren spanning the marker line and the Path.join
  # continuation (path traversal check).
  # ---------------------------------------------------------------------------
  def delete_export(conn) do
    base = Path.expand("/srv/app/exports")
    File.rm!(
      # ubs:ignore -- marker on a physical line of the multi-line statement
      Path.join(base, conn.params["delete"])
    )
  end

  # ---------------------------------------------------------------------------
  # Arrangement 4 -- formatter-relocated marker: the flagged statement is the
  # `if File.exists?(...) do` block opener and the marker sits on the first
  # line inside the block, where mix format relocates it. The same marker is
  # the previous line of the File.rm! finding below it. The blank line after
  # the def is load-bearing: it keeps the flagged opener the first line of
  # its own statement interval.
  # ---------------------------------------------------------------------------
  def maybe_delete(conn) do

    if File.exists?("/srv/app/exports/" <> conn.params["delete"]) do
      # ubs:ignore -- formatter-relocated marker, first line inside the block
      File.rm!("/srv/app/exports/" <> conn.params["delete"])
    end
  end

  # ---------------------------------------------------------------------------
  # Arrangement 5 -- rule-scoped marker on the line above the finding:
  # conn.host folded into an external redirect (open redirect check).
  # ---------------------------------------------------------------------------
  def redirect_host(conn) do
    target = "https://" <> conn.host <> "/dashboard"
    # ubs:ignore[ex.request-open-redirect] -- rule-scoped previous-line marker
    redirect(conn, external: target)
  end

  # ---------------------------------------------------------------------------
  # Arrangement 1b -- trailing marker (bare): request-derived location header
  # sink (open redirect check, put_resp_header family).
  # ---------------------------------------------------------------------------
  def redirect_location_header(conn) do
    location = conn.params["location"]

    conn
    |> put_resp_header("location", location) # ubs:ignore -- trailing marker arrangement
    |> send_resp(302, "")
  end
end
