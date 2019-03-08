defmodule LogicalPermissions.BypassAccessChecker do
  @callback check_bypass_access(Tuple.t) :: {:ok, Boolean.t} | {:error, String.t}
end
