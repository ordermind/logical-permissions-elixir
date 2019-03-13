# bypass access checker that does not adopt the correct behavior
defmodule LogicalPermissions.Test.BypassAccessCheckerInvalidBehavior do
  def check_bypass_access(_) do
    {:ok, true}
  end
end

