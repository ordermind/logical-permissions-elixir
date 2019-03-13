# :flag permission type
defmodule LogicalPermissions.Test.Misc do
  @behaviour LogicalPermissions.PermissionType

  # This example callback assumes that there is a map called "user" inside the context map. If the user has a key which corresponds to the flag, and the value
  # for that key is true, {:ok, true} is returned. In all other cases, {:ok, false} is returned.
  def check_permission(permission, context) do
    case Map.fetch(context.user, String.to_atom(permission)) do
      {:ok, true} -> {:ok, true}
      {:ok, _} -> {:ok, false}
      :error -> {:ok, false}
    end
  end
end

