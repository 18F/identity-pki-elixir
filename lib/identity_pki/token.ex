defmodule IdentityPki.Token do
  @doc """
  Encrypts a JSON-encodable map. By default, an `:expires_at` field
  is added to the JSON to encode an expiry time. Two values with random
  data are also added to the JSON to increase the entropy of the token.

  See `encrypt_text/2` for more information.

  ## Options
    * `:expires_at` - A `NaiveDateTime` that specifies when the token
      expires. Defaults to five minutes in the future with `default_expires_at/0`.
      A token can skip setting the expires date by explicitly passing `nil`.
    * `:secret_key` - The secret key used to encrypt the value. Defaults
      to `secret_key/0`.
  """
  @spec box(map(), keyword()) :: String.t()
  def box(data, opts \\ []) do
    expires_at = Keyword.get_lazy(opts, :expires_at, &default_expires_at/0)
    key = Keyword.get_lazy(opts, :secret_key, &secret_key/0)

    data =
      if expires_at do
        Map.put(data, :expires_at, expires_at)
      else
        data
      end

    json =
      Map.put(data, :r1, random_bytes(8))
      |> Map.put(:r2, random_bytes(8))
      |> Jason.encode!()

    encrypt_text(json, key)
  end

  @doc """
  Decrypts an encrypted URL-encoded JSON-encoded data token generated by `box/2`.
  The token is in the format of `CIPHERTEXT--INITIALIZATIONVECTOR--AUTHENTICATIONTAG`.
  The `with/1` syntax is used
  to process the token and ensure each step is successful before moving on to the next. The sequence
  of operations is:

  1. Split the token into ciphertext, initialization vector, and authentication tag segments
  2. Decode the segments from Base64 format into binary data
  3. Decrypt the token using the Erlang `:crypto` module.
  4. Decode the decrypted data into a JSON map
  5. Check if the token has an expiration in the `"expired_at"` key and whether it is in the past
  6. Drop the "expired_at" key if it exists, and the "r1", "r2" keys that were used to add entropy

  If any of these steps fail, the function falls to the `else` block, and
  `{:error, :failed_to_decrypt}` is returned.

  See `box/2` and `encrypt_text/2` for more information.
  """
  @spec open(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def open(token, key \\ secret_key()) do
    with [text, iv, tag] <- String.split(token, "--"),
         {:ok, text} <- Base.decode64(text),
         {:ok, iv} <- Base.decode64(iv),
         {:ok, tag} <- Base.decode64(tag),
         decrypted when is_binary(decrypted) <-
           :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, text, "", tag, false),
         {:ok, json} <- Jason.decode(decrypted),
         false <- expired_token?(json) do
      {:ok, Map.drop(json, ["r1", "r2", "expires_at"])}
    else
      _ ->
        {:error, :failed_to_decrypt}
    end
  end

  @doc """
  Accepts data, an HMAC-based header, and the shared secret key used to
  generate the HMAC. The HMAC is in the form of "hmac USER:NONCE:HMAC_DIGEST". The HMAC digest
  should be the data and nonce concatenated with a `"+"` and then digested with SHA256 HMAC using
  the shared secret key. This digest is implemented in `build_hmac/3` and should equal the digest
  portion of the HMAC-based header. In most cases, `data` is an encrypted token generated by `box/2`.
  """
  @spec valid_hmac?(String.t(), String.t(), String.t()) :: boolean()
  def valid_hmac?(data, hmac_header, verify_secret \\ secret_verify_key()) do
    with true <- String.starts_with?(hmac_header, "hmac "),
         [_user, nonce, hmac] <- String.split(hmac_header, ":"),
         false <- nonce_seen?(nonce),
         true <- build_hmac(data, nonce, verify_secret) == hmac do
      true
    else
      _e ->
        false
    end
  end

  @doc """
  Encrypts a blob of data with the secret key argument. The encryption
  uses AES256-GCM with a 12 byte initialization vector and 16 byte authentication
  tag. The ciphertext, authentication tag, and initialization vector are Base64
  encoded and concatenated.
  """
  @spec encrypt_text(String.t(), String.t()) :: String.t()
  def encrypt_text(data, secret_key) do
    iv = :crypto.strong_rand_bytes(12)

    {cipher_text, authentication_tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, data, "", 16, true)

    [Base.encode64(cipher_text), Base.encode64(iv), Base.encode64(authentication_tag)]
    |> Enum.join("--")
  end

  def nonce_seen?(_nonce) do
    false
  end

  def build_hmac(data, nonce, verify_secret) do
    data = Enum.join([data, nonce], "+")

    :crypto.mac(:hmac, :sha256, verify_secret, data)
    |> Base.url_encode64()
  end

  @spec expired_token?(map()) :: boolean()
  defp expired_token?(map) when not is_map_key(map, "expires_at") do
    false
  end

  defp expired_token?(map) do
    now = NaiveDateTime.utc_now()

    with expires_at <- Map.fetch!(map, "expires_at"),
         {:ok, date_time} <- NaiveDateTime.from_iso8601(expires_at),
         :lt <- NaiveDateTime.compare(now, date_time) do
      false
    else
      _ ->
        true
    end
  end

  @spec secret_key() :: String.t()
  defp secret_key do
    case Application.fetch_env(:identity_pki, :generated_secret_key) do
      {:ok, value} ->
        value

      :error ->
        secret_key = generate_secret_key()
        :ok = Application.put_env(:identity_pki, :generated_secret_key, secret_key)
        secret_key
    end
  end

  defp generate_secret_key do
    salt = Application.get_env(:identity_pki, :token_encryption_key_salt)
    pepper = Application.get_env(:identity_pki, :token_encryption_key_pepper)
    Plug.Crypto.KeyGenerator.generate(pepper, salt, digest: :sha, iterations: 65_536)
  end

  defp secret_verify_key do
    Application.get_env(:identity_pki, :verify_token_secret)
  end

  defp random_bytes(bytes) do
    :crypto.strong_rand_bytes(bytes)
    |> Base.encode64()
  end

  defp default_expires_at do
    NaiveDateTime.utc_now()
    |> NaiveDateTime.add(300, :second)
  end
end
