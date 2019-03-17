defmodule LogicalPermissions.Test.BypassAccessChecker do
  @behaviour LogicalPermissions.BypassAccessChecker

  def check_bypass_access(context) when is_map(context) do
    {:ok, Map.get(context, :bypass_access, true)}
  end
  def check_bypass_access(_) do
    {:error, "The context parameter must be a map."}
  end
end
