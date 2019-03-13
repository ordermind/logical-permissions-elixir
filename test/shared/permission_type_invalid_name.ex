# permission type for testing invalid permission name
defmodule LogicalPermissions.Test.InvalidName do
  @behaviour LogicalPermissions.PermissionType

  def check_permission(_, _) do
    {:ok, true}
  end
end



