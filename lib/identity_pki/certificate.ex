defmodule IdentityPki.Certificate do
  alias IdentityPki.CertificateStore

  @type t :: X509.Certificate.t()

  def issuer(cert) do
    X509.Certificate.issuer(cert)
    |> X509.RDNSequence.to_string()
  end

  def key_id(cert) do
    case X509.Certificate.extension(cert, :subject_key_identifier) do
      # Key id is a binary and needs to be Base16 encoded
      {:Extension, _oid, _critical, key_id} ->
        Base.encode16(key_id)
        |> String.codepoints()
        |> Enum.chunk_every(2)
        |> Enum.map(&Enum.join/1)
        |> Enum.join(":")

      _ ->
        nil
    end
  end

  def signing_key_id(cert) do
    case X509.Certificate.extension(cert, :authority_key_identifier) do
      # Key id is a binary and needs to be Base16 encoded
      {:Extension, _oid, _critical, {:AuthorityKeyIdentifier, key_id, _, _}} ->
        Base.encode16(key_id)
        |> String.codepoints()
        |> Enum.chunk_every(2)
        |> Enum.map(&Enum.join/1)
        |> Enum.join(":")

      _ ->
        nil
    end
  end

  def validate_piv_cac_certificate(cert) do
    case validate_leaf_cert(cert) do
      {:ok, signing_cert} ->
        validate_certificate_chain(signing_cert)

      error ->
        error
    end
  end

  def validate_certificate_chain(cert) do
    rfc_2253_subject(cert)

    # && not expired
    if CertificateStore.root_cert?(cert) do
      validate_root_cert(cert)
    else
      case validate_non_leaf_cert(cert) do
        {:ok, signing_cert} ->
          validate_certificate_chain(signing_cert)

        error ->
          error
      end
    end
  end

  def validate_root_cert(cert) do
    case expired?(cert) do
      :ok ->
        :ok

      {:error, :expired} ->
        "expired"
    end
  end

  def validate_leaf_cert(cert) do
    with :ok <- expired?(cert),
         :ok <- self_signed?(cert),
         :ok <- not_root_cert?(cert),
         {:ok, signing_cert} <- verified_signature?(cert) do
      {:ok, signing_cert}
    else
      {:error, :expired} ->
        "expired"

      {:error, :self_signed} ->
        "self-signed cert"

      {:error, :unverified_signature} ->
        "unverified"

      {:error, :root_cert} ->
        "root cert"
    end

    # |> revoked?
    # |> bad_policy?
  end

  def validate_non_leaf_cert(cert) do
    with :ok <- expired?(cert),
         :ok <- self_signed?(cert),
         {:ok, signing_cert} <- verified_signature?(cert) do
      {:ok, signing_cert}
    else
      {:error, :expired} ->
        "expired"

      {:error, :self_signed} ->
        "self-signed cert"

      {:error, :unverified_signature} ->
        "unverified"
    end

    # |> trusted_root?
    # |> self_signed?
    # |> unverified_signature?
    # |> revoked?
  end

  def not_root_cert?(cert) do
    if CertificateStore.root_cert?(cert) do
      {:error, :root_cert}
    else
      :ok
    end
  end

  @spec expired?(t()) :: :ok | {:error, :expired}
  def expired?(cert) do
    # {:Validity, {:utcTime, '201001143318Z'}, {:utcTime, '231001150126Z'}}
    now = DateTime.utc_now()

    with {:Validity, not_before, not_after} <- X509.Certificate.validity(cert),
         not_before <- X509.DateTime.to_datetime(not_before),
         not_after <- X509.DateTime.to_datetime(not_after),
         :lt <- DateTime.compare(not_before, now),
         :lt <- DateTime.compare(now, not_after) do
      :ok
    else
      _ ->
        {:error, :expired}
    end
  end

  @spec self_signed?(t()) :: :ok | {:error, :self_signed}
  def self_signed?(cert) do
    key_id = IdentityPki.Certificate.key_id(cert)
    signing_key_id = IdentityPki.Certificate.signing_key_id(cert)

    if key_id != signing_key_id do
      :ok
    else
      {:error, :self_signed}
    end
  end

  @spec verified_signature?(t()) :: {:ok, t()} | {:error, :unverified_signature}
  def verified_signature?(cert) do
    signing_cert_key_id = signing_key_id(cert)
    cert_as_der = X509.Certificate.to_der(cert)

    with {:ok, signing_cert} <- CertificateStore.fetch(signing_cert_key_id),
         signing_public_key <- X509.Certificate.public_key(signing_cert),
         true <- :public_key.pkix_verify(cert_as_der, signing_public_key) do
      {:ok, signing_cert}
    else
      _ ->
        {:error, :unverified_signature}
    end
  end

  @spec revoked?(t()) :: :ok | {:error, :revoked}
  def revoked?(_cert) do
    :ok
  end

  @spec bad_policy?(t()) :: :ok | {:error, :bad_policy}
  def bad_policy?(_cert) do
    :ok
  end

  @doc """
  SHA512 digests the RFC 2253 formatted subject of a certificate.

  The digest is Base64 encoded, but a `"\n"` is added every 60 characters
  to match the behavior of Ruby's `Base64.encode64`
  """
  @spec dn_signature(X509.Certificate.t()) :: String.t()
  def dn_signature(cert) do
    subject = rfc_2253_subject(cert)

    :crypto.hash(:sha512, subject)
    |> Base.encode64()
    |> String.codepoints()
    |> Enum.chunk_every(60)
    |> Enum.join("\n")
  end

  def auth_cert?(cert) do
    not is_nil(X509.Certificate.extension(cert, {1, 3, 6, 1, 5, 2, 3, 4}))
  end

  def rfc_2253_subject(cert) do
    {:rdnSequence, rdnSequence} = X509.Certificate.subject(cert)

    rdnSequence
    |> Enum.map(fn attribute_type_and_value_list ->
      Enum.map(attribute_type_and_value_list, fn {:AttributeTypeAndValue, oid, value} ->
        oid = oid_to_string(oid)
        value = value_to_string(value)
        "#{oid}=#{value}"
      end)
      |> Enum.reverse()
      |> Enum.join("+")
    end)
    |> Enum.reverse()
    |> Enum.join(",")
  end

  def subject(cert) do
    {:rdnSequence, rdnSequence} = X509.Certificate.subject(cert)

    subject =
      rdnSequence
      |> Enum.map(fn attribute_type_and_value_list ->
        Enum.map(attribute_type_and_value_list, fn {:AttributeTypeAndValue, oid, value} ->
          oid = oid_to_string(oid)
          value = value_to_string(value)
          "#{oid}=#{value}"
        end)
      end)
      |> List.flatten()
      |> Enum.join("/")

    "/" <> subject
  end

  def oid_to_string({2, 5, 4, 3}), do: "CN"
  def oid_to_string({2, 5, 4, 6}), do: "C"
  def oid_to_string({2, 5, 4, 7}), do: "L"
  def oid_to_string({2, 5, 4, 8}), do: "ST"
  def oid_to_string({2, 5, 4, 9}), do: "STREET"
  def oid_to_string({2, 5, 4, 10}), do: "O"
  def oid_to_string({2, 5, 4, 11}), do: "OU"
  def oid_to_string({0, 9, 2342, 19_200_300, 100, 1, 1}), do: "UID"
  def oid_to_string({0, 9, 2342, 19_200_300, 100, 1, 25}), do: "DC"

  def oid_to_string(tuple) do
    Tuple.to_list(tuple)
    |> Enum.map(&Integer.to_string/1)
    |> Enum.join(".")
  end

  def value_to_string(charlist) when is_list(charlist) do
    List.to_string(charlist)
  end

  def value_to_string({:printableString, charlist}) do
    List.to_string(charlist)
  end

  def value_to_string(<<19, 14, rest::binary>>) do
    if String.valid?(rest) do
      rest
    else
      :error
    end
  end
end
