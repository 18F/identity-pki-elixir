defmodule IdentityPki.Token do
  def box(data, opts \\ []) do
    expires_at = Keyword.get(opts, :expires_at)
    key = Keyword.get_lazy(opts, :key, &secret_key/0)

    data =
      if expires_at do
        Map.put(data, :expires_at, expires_at)
      else
        expires_at =
          NaiveDateTime.utc_now()
          |> NaiveDateTime.add(300, :second)

        Map.put(data, :expires_at, expires_at)
      end

    json =
      Map.put(data, :r1, random_bytes(8))
      |> Map.put(:r2, random_bytes(8))
      |> Jason.encode!()

    encrypt_text(json, key)
  end

  @spec open(String.t(), String.t()) :: {:ok, Map.t()} | {:error, atom()}
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

  @spec valid_hmac?(String.t(), String.t(), String.t()) :: boolean()
  def valid_hmac?(token, hmac_header, verify_secret \\ secret_verify_key()) do
    # "hmac #{user}:#{nonce}:#{digest}"
    with true <- String.starts_with?(hmac_header, "hmac "),
         [_user, nonce, hmac] <- String.split(hmac_header, ":"),
         false <- nonce_seen?(nonce),
         true <- build_hmac(token, nonce, verify_secret) == hmac do
      true
    else
      _e ->
        false
    end
  end

  def encrypt_text(data, key) do
    iv = :crypto.strong_rand_bytes(12)
    # 16 bytes encryption tag length
    {cipher_text, cipher_tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, data, "", 16, true)

    [Base.encode64(cipher_text), Base.encode64(iv), Base.encode64(cipher_tag)]
    |> Enum.join("--")
  end

  def nonce_seen?(_nonce) do
    false
  end

  def build_hmac(token, nonce, verify_secret) do
    data = Enum.join([token, nonce], "+")

    :crypto.mac(:hmac, :sha256, verify_secret, data)
    |> Base.url_encode64()
  end

  @spec expired_token?(Map.t()) :: boolean()
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

  defp secret_key do
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
end
