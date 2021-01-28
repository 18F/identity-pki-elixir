defmodule IdentityPkiWeb.PageController do
  use IdentityPkiWeb, :controller
  alias IdentityPki.{Certificate, PivCac}

  def identify(conn, params) do
    header_referer = Plug.Conn.get_req_header(conn, "referer")
                     |> List.first()
    params = Map.put_new(params, "redirect_uri", header_referer)

    with {:ok, params} <- IdentityPkiWeb.IdentifyValidator.index(params),
         [cert_header] <- Plug.Conn.get_req_header(conn, "x-client-cert"),
         {:ok, cert} <- process_cert(cert_header),
         distinguished_name_signature <- Certificate.dn_signature(cert),
         {:ok, piv} <- PivCac.find_or_create(distinguished_name_signature) do
      token =
        %{
          subject: Certificate.rfc_2253_subject(cert),
          issuer: Certificate.issuer(cert),
          uuid: piv.uuid,
          card_type: "piv",
          auth_cert: Certificate.auth_cert?(cert),
          nonce: params.nonce
        }
        |> IdentityPki.Token.box()

      query = URI.encode_query(%{token: token})
      referrer = %{params.referrer | query: query}

      redirect(conn, external: URI.to_string(referrer))
    else
      _ ->
        text(conn, "")
    end
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

  defp process_cert(cert_header) do
    URI.decode(cert_header)
    |> X509.Certificate.from_pem
  end
end
