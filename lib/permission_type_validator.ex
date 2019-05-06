defmodule LogicalPermissions.PermissionTypeValidator do
  reserved_permission_keys = [:no_bypass, :and, :nand, :or, :nor, :xor, :not]

  def unquote(:is_valid)({name}) do
    case name in unquote(reserved_permission_keys) do
      true -> {:error, "The name of a permission type cannot be one of the following: #{inspect(unquote(reserved_permission_keys))}"}
      _ -> {:ok, true}
    end
  end

  def unquote(:get_reserved_permission_keys)() do
    unquote(reserved_permission_keys)
  end
end
