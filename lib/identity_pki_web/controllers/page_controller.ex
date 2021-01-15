defmodule IdentityPkiWeb.PageController do
  use IdentityPkiWeb, :controller

  def identify(conn, params) do
    IO.inspect(conn.req_headers)
    text(conn, "")
  end

  def verify(conn, params) do

  end

  defp referrer(conn, params) do
    header_referrer = Plug.Conn.get_req_header(conn, "Referer")                      |> List.first()

    param_referrer = Map.get(params, "redirect_uri")
    referrer = header_referrer || param_referrer

    uri = URI.parse(referrer)
    uri
  end
end
