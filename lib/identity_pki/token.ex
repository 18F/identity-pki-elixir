defmodule IdentityPki.Token do
  def box(data, opts \\ []) do
    expires_at = Keyword.get(opts, :expires_at)
    key = Keyword.get_lazy(opts, :key, &secret_key/0)

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

  def open(token, key \\ secret_key()) do
    # TODO: check expires_at
    # TODO: check HMAC
    [text, iv, tag] =
      String.split(token, "--")
      |> Enum.map(&Base.decode64!/1)

    :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, text, "", tag, false)
    |> Jason.decode!()
    |> Map.drop(["r1", "r2"])
  end

  def encrypt_text(data, key) do
    iv = :crypto.strong_rand_bytes(12)
    # 16 bytes encryption tag length
    {cipher_text, cipher_tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, data, "", 16, true)

    [Base.encode64(cipher_text), Base.encode64(iv), Base.encode64(cipher_tag)]
    |> Enum.join("--")
  end

  defp secret_key do
    salt = Application.get_env(:identity_pki, :token_encryption_key_salt)
    pepper = Application.get_env(:identity_pki, :token_encryption_key_pepper)
    Plug.Crypto.KeyGenerator.generate(pepper, salt, digest: :sha, iterations: 65_536)
  end

  defp random_bytes(bytes) do
    :crypto.strong_rand_bytes(bytes)
    |> Base.encode64()
  end
end
