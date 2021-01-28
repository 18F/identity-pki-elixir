defmodule IdentityPki.PivCac do
  use Ecto.Schema
  import Ecto.Changeset

  @timestamps_opts [inserted_at: false, updated_at: false]

  schema "piv_cacs" do
    field :uuid, :string
    field :dn_signature, :string
    timestamps()
  end

  @doc false
  def create_changeset(piv_cac, attrs) do
    piv_cac
    |> cast(attrs, [:dn_signature])
    |> put_change(:uuid, Ecto.UUID.generate())
    |> validate_required([:uuid, :dn_signature])
    |> unique_constraint(:uuid)
    |> unique_constraint(:dn_signature)
  end

  @doc """
  This should be made to be safe from race conditions.
  """
  def find_or_create(dn_signature) do
    case IdentityPki.Repo.get_by(__MODULE__, dn_signature: dn_signature) do
      nil ->
        create_changeset(%__MODULE__{}, %{dn_signature: dn_signature})
        |> IdentityPki.Repo.insert()

      %__MODULE__{} = piv_cac ->
        {:ok, piv_cac}
    end
  end
end
