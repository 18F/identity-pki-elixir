defmodule IdentityPki.TokenTest do
  use ExUnit.Case, async: true

  alias IdentityPki.Token

  @data %{
    "a" => "b",
    "c" => 1
  }

  describe "box/open" do
    test "can decode an encoded token" do
      encrypted = Token.box(@data)

      assert Token.open(encrypted) == {:ok, @data}
    end

    test "rejects expired token" do
      expires_at =
        NaiveDateTime.utc_now()
        |> NaiveDateTime.add(-10, :second)

      encrypted = Token.box(@data, expires_at: expires_at)

      assert Token.open(encrypted) == {:error, :failed_to_decrypt}
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
      hmac_header = "hmac :#{nonce}:#{digest}1"
      bad_data = "abcd"

      assert Token.valid_hmac?(bad_data, hmac_header, secret) == false
    end

    test "tampered nonce fails" do
      data = "abc"
      nonce = "ab"
      secret = "abcd"
      digest = Token.build_hmac(data, nonce, secret)
      bad_nonce = "abcd"
      hmac_header = "hmac :#{bad_nonce}:#{digest}1"

      assert Token.valid_hmac?(data, hmac_header, secret) == false
    end
  end
end
