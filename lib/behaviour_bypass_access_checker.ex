defmodule LogicalPermissions.BypassAccessChecker do
  @callback check_bypass_access(map()) :: {:ok, boolean()} | {:error, binary()}
end
