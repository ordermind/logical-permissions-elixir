# permission type for testing catching invalid return values

defmodule LogicalPermissions.Test.InvalidReturnValue do
  @behaviour LogicalPermissions.PermissionType

  @dialyzer {:nowarn_function, check_permission: 2}
  def check_permission(_, _) do
    {:ok, "invalid_return_value"}
  end
end
