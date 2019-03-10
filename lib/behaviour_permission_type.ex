defmodule LogicalPermissions.PermissionType do
  @callback check_permission(String.t, Map.t) :: {:ok, Boolean.t} | {:error, String.t}
end
