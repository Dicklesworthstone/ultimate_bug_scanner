defmodule CleanHeaderInjection do
  import Plug.Conn

  @allowed_redirect_hosts MapSet.new(["app.example.com", "accounts.example.com"])

  def safe_header_value(raw) do
    raw
    |> String.replace("\r", "")
    |> String.replace("\n", "")
  end

  def encoded_filename(raw) do
    URI.encode(raw)
  end

  def reject_crlf(value) do
    if String.contains?(value, "\r") or String.contains?(value, "\n") do
      raise ArgumentError, "invalid header"
    end

    value
  end

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

  def display_name(conn) do
    name = safe_header_value(conn.params["display_name"] || "guest")

    conn
    |> put_resp_header("x-display-name", name)
    |> send_resp(200, "ok")
  end

  def download(conn) do
    filename = encoded_filename(Map.get(conn.query_params, "filename") || "report.csv")

    conn
    |> put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
    |> send_resp(200, "ok")
  end

  def trace_header(conn) do
    trace =
      conn
      |> Plug.Conn.get_req_header("x-trace-id")
      |> List.first()
      |> safe_header_value()

    Plug.Conn.put_resp_header(conn, "x-upstream-trace", trace)
  end

  def cookie_header(conn) do
    export_name = safe_header_value(conn.cookies["export_name"] || "report")
    put_resp_header(conn, "x-export-name", export_name)
  end

  def content_type(conn) do
    media_type = safe_header_value(conn.params["content_type"] || "text/plain")
    put_resp_content_type(conn, media_type)
  end

  def rejected_customer_header(conn) do
    value = conn.params["customer"] |> reject_crlf()
    put_resp_header(conn, "x-customer", value)
  end

  def location_only(conn) do
    target = safe_redirect_url(conn.params["location"] || "/")

    conn
    |> put_resp_header("location", target)
    |> send_resp(302, "")
  end
end
