defmodule IdentityPki.Repo do
  use Ecto.Repo,
    otp_app: :identity_pki,
    adapter: Ecto.Adapters.Postgres
end
