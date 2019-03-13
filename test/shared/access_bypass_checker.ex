defmodule LogicalPermissions.Test.BypassAccessChecker do
  @behaviour LogicalPermissions.BypassAccessChecker

  def check_bypass_access(context) do
    {:ok, Map.get(context, :bypass_access, true)}
  end
end
