# bypass access checker for testing catching invalid return values

defmodule LogicalPermissions.Test.BypassAccessCheckerInvalidReturnValue do
  @behaviour LogicalPermissions.BypassAccessChecker

  def check_bypass_access(_) do
    {:ok, "invalid_return_value"}
  end
end

