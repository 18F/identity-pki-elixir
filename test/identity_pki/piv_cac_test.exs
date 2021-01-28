defmodule IdentityPki.PivCacTest do
  use IdentityPki.DataCase, async: true

  alias IdentityPki.PivCac

  describe "find_or_create/1" do
    test "returns existing PivCac if dn already exists" do
      {:ok, piv} = PivCac.find_or_create("test")

      {:ok, second_piv} = PivCac.find_or_create("test")

      assert piv.uuid == second_piv.uuid
    end
  end
end
