defmodule IdentityPki.CertificateAuthority do
  use Ecto.Schema

  schema "certificate_authorities" do
    field :key, :string
  end
end
