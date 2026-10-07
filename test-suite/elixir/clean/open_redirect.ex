defmodule CleanOpenRedirect do
  import Phoenix.Controller
  import Plug.Conn

  @allowed_redirect_hosts MapSet.new(["app.example.com", "accounts.example.com"])

  def safe_redirect_url(raw) do
    if String.contains?(raw, ["\\", "\n", "\r", "\t"]) do
      raise ArgumentError, "ambiguous redirect characters"
    end

    if String.starts_with?(raw, "/") and not String.starts_with?(raw, "//") do
      raw
    else
      uri = URI.parse(raw)

      unless uri.scheme == "https" and MapSet.member?(@allowed_redirect_hosts, uri.host) do
        raise ArgumentError, "blocked redirect"
      end

      raw
    end
  end

  def helper_validated_query(conn) do
    target = safe_redirect_url(conn.params["next"] || "/")
    redirect(conn, to: target)
  end

  def helper_validated_header(conn) do
    target =
      conn
      |> Plug.Conn.get_req_header("x-redirect-url")
      |> List.first()
      |> safe_redirect_url()

    Phoenix.Controller.redirect(conn, external: target)
  end

  def helper_validated_query_params(conn) do
    target = safe_redirect_url(Map.get(conn.query_params, "return_to") || "/")
    redirect(conn, external: target)
  end

  def inline_local_guard(conn) do
    target = conn.params["continue"] || "/"

    unless String.starts_with?(target, "/") and not String.starts_with?(target, "//") and
             not String.contains?(target, ["\\", "\n", "\r", "\t"]) do
      raise ArgumentError, "blocked redirect"
    end

    redirect(conn, to: target)
  end

  def inline_host_allowlist(conn) do
    target = conn.params["return_url"] || "https://app.example.com/dashboard"
    uri = URI.parse(target)

    unless uri.scheme == "https" and MapSet.member?(@allowed_redirect_hosts, uri.host) and
             not String.contains?(target, ["\\", "\n", "\r", "\t"]) do
      raise ArgumentError, "blocked redirect"
    end

    redirect(conn, external: target)
  end

  def validated_location_header(conn) do
    location = safe_redirect_url(conn.params["location"] || "/")

    conn
    |> put_resp_header("location", location)
    |> send_resp(302, "")
  end
end
