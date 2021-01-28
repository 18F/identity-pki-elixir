defmodule IdentityPki.Certificate do
  @type t :: X509.Certificate.t()

  @spec issuer(t()) :: String.t()
  def issuer(cert) do
    X509.Certificate.issuer(cert)
    |> X509.RDNSequence.to_string()
  end

  @spec key_id(t()) :: String.t() | nil
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

  @spec signing_key_id(t()) :: String.t() | nil
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

  def validate_leaf_cert(cert) do
    cert
    # |> expired?
    # |> self_signed?
    # |> unverified_signature? # fetch signing cert and validate_non_leaf
    # |> revoked?
    # |> bad_policy?
  end

  def validate_non_leaf_cert(cert) do
    cert
    # |> expired?
    # |> trusted_root?
    # |> self_signed?
    # |> unverified_signature?
    # |> revoked?
  end

  @doc """
  SHA512 digests the RFC 2253 formatted subject of a certificate.

  The digest is Base64 encoded, but a `"\n"` is added every 60 characters
  to match the behavior of Ruby's `Base64.encode64`
  """
  @spec dn_signature(t()) :: String.t()
  def dn_signature(cert) do
    subject = rfc_2253_subject(cert)

    :crypto.hash(:sha512, subject)
    |> Base.encode64()
    |> String.codepoints()
    |> Enum.chunk_every(60)
    |> Enum.join("\n")
  end

  @doc """
  Checks if the cert has an extension with the "client authentication" OID
  """
  @spec auth_cert?(t()) :: boolean()
  def auth_cert?(cert) do
    not is_nil(X509.Certificate.extension(cert, {1, 3, 6, 1, 5, 2, 3, 4}))
  end

  @spec rfc_2253_subject(t()) :: String.t()
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

  @spec subject(t()) :: String.t()
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

  @spec oid_to_string(tuple()) :: String.t()
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
