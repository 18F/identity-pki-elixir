defmodule IdentityPkiWeb.PageController do
  use IdentityPkiWeb, :controller
  alias IdentityPki.Certificate

  def identify(conn, params) do
    referrer_uri = referrer(conn, params)

    nonce = Map.get(params, "nonce")

    [cert] = Plug.Conn.get_req_header(conn, "x-client-cert")

    cert =
      URI.decode(cert)
      |> X509.Certificate.from_pem!()

    token =
      %{
        subject: Certificate.rfc_2253_subject(cert),
        issuer: Certificate.issuer(cert),
        uuid: "c229c00a-5b80-424c-aa5c-f5a0e97e9fa1",
        card_type: "piv",
        auth_cert: Certificate.auth_cert?(cert),
        nonce: nonce
      }
      |> IdentityPki.Token.box()

    query = URI.encode_query(%{token: token})
    referrer = %{referrer_uri | query: query}

    redirect(conn, external: URI.to_string(referrer))
  end

  def verify(conn, params) do
    authentication_headers = Plug.Conn.get_req_header(conn, "authentication")

    token = Map.get(params, "token")

    with true <- valid_hmac?(token, authentication_headers),
         {:ok, json} <- IdentityPki.Token.open(token) do
      json(conn, json)
    end
  end

  # Since the same request header can appear multiple times, only match
  # and attempt validation when there is only one value.
  @spec valid_hmac?(String.t(), list(String.t())) :: boolean()
  defp valid_hmac?(token, [authentication_header]) do
    IdentityPki.Token.valid_hmac?(token, authentication_header)
  end

  defp valid_hmac?(_token, _auth_headers), do: false

  defp referrer(conn, params) do
    header_referrer =
      Plug.Conn.get_req_header(conn, "referer")
      |> List.first()

    param_referrer = Map.get(params, "redirect_uri")
    referrer = header_referrer || param_referrer

    URI.parse(referrer)
  end
end
