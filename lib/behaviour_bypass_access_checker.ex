defmodule LogicalPermissions.BypassAccessChecker do
  @callback check_bypass_access(Map.t) :: {:ok, Boolean.t} | {:error, String.t}
end
