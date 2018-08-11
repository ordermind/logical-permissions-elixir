defmodule LogicalPermissions.PermissionType do
  @callback check_permission?(String.t, Tuple.t) :: {:ok, Boolean.t} | {:error, String.t}
end
