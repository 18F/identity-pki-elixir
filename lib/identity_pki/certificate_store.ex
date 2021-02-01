defmodule IdentityPki.CertificateStore do
  @certificate_path "./priv/certificates/*.pem"

  @spec map() :: %{String.t() => IdentityPki.Certificate.t()}
  def map do
    case Application.fetch_env(:identity_pki, :certificates) do
      {:ok, value} ->
        value

      :error ->
        certs = load()
        :ok = Application.put_env(:identity_pki, :certificates, certs)
        certs
    end
  end

  @spec fetch(String.t()) :: {:ok, IdentityPki.Certificate.t()} | :error
  def fetch(key) do
    Map.fetch(map(), key)
  end

  @spec load() :: %{String.t() => IdentityPki.Certificate.t()}
  def load do
    Path.wildcard(@certificate_path)
    |> Enum.map(fn path ->
      cert =
        File.read!(path)
        |> X509.Certificate.from_pem!()

      key = IdentityPki.Certificate.key_id(cert)
      {key, cert}
    end)
    |> Enum.into(%{})
  end

  @spec root_cert?(IdentityPki.Certificate.t()) :: boolean
  def root_cert?(cert) do
    key_id = IdentityPki.Certificate.key_id(cert)
    root_cert_ids = Application.get_env(:identity_pki, :trusted_ca_root_certificate_ids)

    if key_id in root_cert_ids do
      true
    else
      false
    end
  end
end
