defmodule IdentityPki.CertificateRevocation do
  use Ecto.Schema
  import Ecto.Query

  schema "certificate_revocations" do
    field :serial, :string
  end

  def revoked?(cert) do
    signing_key_id = IdentityPki.Certificate.signing_key_id(cert)
    serial = "#{X509.Certificate.serial(cert)}"

    revocation =
      from(cr in IdentityPki.CertificateRevocation,
        join: ca in IdentityPki.CertificateAuthority,
        on: ca.id == cr.certificate_authority_id,
        where: ca.key == ^signing_key_id and cr.serial == ^serial
      )
      |> IdentityPki.Repo.one()

    !is_nil(revocation)
  end
end
