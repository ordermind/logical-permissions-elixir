# :role permission type
defmodule LogicalPermissions.Test.Role do
  @behaviour LogicalPermissions.PermissionType

  # This example callback assumes that there is a map called "user" inside the context map, which contains a :roles list
  def check_permission(role, context) do
    case Map.fetch(context.user, :roles) do
      {:ok, roles} -> {:ok, Enum.member?(roles, role)}
      :error -> {:ok, false}
    end
  end
end
