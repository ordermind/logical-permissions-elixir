# permission type that does not adopt the correct behavior

defmodule LogicalPermissions.Test.InvalidBehavior do
  def check_permission(_, _) do
    {:ok, true}
  end
end
