defmodule IdentityPki.TokenTest do
  use ExUnit.Case, async: true

  alias IdentityPki.Token

  @data %{
    "a" => "b",
    "c" => 1
  }
  @secret_key <<109, 186, 109, 204, 105, 247, 43, 210, 48, 152, 199, 233, 28, 52, 189, 242, 30,
                231, 57, 214, 226, 20, 119, 196, 223, 163, 41, 150, 114, 143, 97, 46>>

  describe "box/open" do
    test "can decode an encoded token" do
      encrypted = Token.box(@data, secret_key: @secret_key)

      assert Token.open(encrypted, @secret_key) == {:ok, @data}
    end

    test "rejects expired token" do
      expires_at =
        NaiveDateTime.utc_now()
        |> NaiveDateTime.add(-10, :second)

      encrypted = Token.box(@data, expires_at: expires_at, secret_key: @secret_key)

      assert Token.open(encrypted, @secret_key) == {:error, :failed_to_decrypt}
    end
  end

  describe "valid_hmac?/3" do
    test "verifies HMAC" do
      data = "abc"
      nonce = "ab"
      secret = "abcd"
      digest = Token.build_hmac(data, nonce, secret)
      hmac_header = "hmac :#{nonce}:#{digest}"

      assert Token.valid_hmac?(data, hmac_header, secret) == true
    end

    test "tampered data fails" do
      data = "abc"
      nonce = "ab"
      secret = "abcd"
      digest = Token.build_hmac(data, nonce, secret)
      hmac_header = "hmac :#{nonce}:#{digest}"
      bad_data = "abcd"

      assert Token.valid_hmac?(bad_data, hmac_header, secret) == false
    end

    test "tampered nonce fails" do
      data = "abc"
      nonce = "ab"
      secret = "abcd"
      digest = Token.build_hmac(data, nonce, secret)
      bad_nonce = "abcd"
      hmac_header = "hmac :#{bad_nonce}:#{digest}"

      assert Token.valid_hmac?(data, hmac_header, secret) == false
    end
  end
end
