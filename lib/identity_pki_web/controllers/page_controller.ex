defmodule IdentityPkiWeb.PageController do
  use IdentityPkiWeb, :controller
  alias IdentityPki.Certificate

  def identify(conn, params) do
    referrer_uri = referrer(conn, params)
    referrer = %{referrer_uri | query: "token=1234"}

    nonce = Map.get(params, "nonce")

    [cert] = Plug.Conn.get_req_header(conn, "x-client-cert")

    cert =
      URI.decode(cert)
      |> X509.Certificate.from_pem!()

    token = %{
      subject: Certificate.rfc_2253_subject(cert),
      issuer: Certificate.issuer(cert),
      uuid: "c229c00a-5b80-424c-aa5c-f5a0e97e9fa1",
      card_type: "piv",
      auth_cert: Certificate.auth_cert?(cert),
      nonce: nonce
    }

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
    header_referrer =
      Plug.Conn.get_req_header(conn, "referer")
      |> List.first()

    param_referrer = Map.get(params, "redirect_uri")
    referrer = header_referrer || param_referrer

    uri = URI.parse(referrer)
    uri
  end
end
