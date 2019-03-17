defmodule LogicalPermissions.PermissionType do
  @callback check_permission(binary(), map()) :: {:ok, boolean()} | {:error, binary()}
end
