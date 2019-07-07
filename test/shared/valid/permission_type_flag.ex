# :flag permission type
defmodule LogicalPermissions.Test.Flag do
  @behaviour LogicalPermissions.PermissionType

  # This example callback assumes that there is a map called "user" inside the context map. If the user has a key which corresponds to the flag, and the value
  # for that key is true, {:ok, true} is returned. In all other cases, {:ok, false} is returned. Both strings and atoms are supported for flag values.
  def check_permission(flag, context)
  def check_permission(flag, context) when is_binary(flag) do
    check_permission(String.to_atom(flag), context)
  end
  def check_permission(flag, context) when is_atom(flag) do
    case Map.fetch(context.user, flag) do
      {:ok, true} -> {:ok, true}
      {:ok, _} -> {:ok, false}
      :error -> {:ok, false}
    end
  end
end
