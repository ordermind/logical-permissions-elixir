defmodule LogicalPermissions.Test.BypassAccessChecker do
  @behaviour LogicalPermissions.BypassAccessChecker

  def check_bypass_access(context) do
    case Map.get(context, :error) do
      nil -> {:ok, Map.get(context, :bypass_access, true)}
      reason -> {:error, reason}
    end
  end
end
