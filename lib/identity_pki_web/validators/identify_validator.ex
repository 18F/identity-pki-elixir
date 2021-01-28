defmodule IdentityPkiWeb.IdentifyValidator do
  alias Ecto.Changeset

  def index(params) do
    types = %{
      nonce: :string,
      referrer: :string
    }

    data = %{}

    {data, types}
    |> Changeset.cast(params, [:nonce, :referrer])
    |> Changeset.validate_length(:nonce, min: 4)
    |> Changeset.apply_action(:insert)
  end
end
