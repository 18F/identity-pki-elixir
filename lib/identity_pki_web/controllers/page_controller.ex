defmodule IdentityPkiWeb.PageController do
  use IdentityPkiWeb, :controller

  def identify(conn, params) do
    referrer_uri = referrer(conn, params)
    referrer = %{referrer_uri | query: "token=1234"}

    [cert] = Plug.Conn.get_req_header(conn, "x-client-cert")

    cert = URI.decode(cert)

    redirect(conn, external: URI.to_string(referrer))
  end

  def verify(conn, params) do
    # json = %{
    #   nonce: nonce,
    #   is_auth_cert: cert.auth_cert?
    #   subject: subject_s,
    #   issuer: issuer.to_s,
    #   uuid: piv.uuid,
    #   card_type: card_type
    # }
    json = %{
      nonce: "abc123",
      is_auth_cert: true,
      subject: "subject",
      issuer: "issuer",
      uuid: "1234-5678-1234-1234",
      card_type: "piv"
    }

    json(conn, json)
  end

  defp referrer(conn, params) do
    header_referrer = Plug.Conn.get_req_header(conn, "referer")
                      |> List.first()

    param_referrer = Map.get(params, "redirect_uri")
    referrer = header_referrer || param_referrer

    uri = URI.parse(referrer)
    uri
  end
end
