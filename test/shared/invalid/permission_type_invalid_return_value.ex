# permission type for testing catching invalid return values

defmodule LogicalPermissions.Test.InvalidReturnValue do
  @behaviour LogicalPermissions.PermissionType

  def check_permission(_, _) do
    {:ok, "invalid_return_value"}
  end
end


