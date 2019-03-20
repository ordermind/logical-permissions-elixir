defmodule LogicalPermissions.PermissionTypeValidator do
  reserved_permission_keys = [:no_bypass, :and, :nand, :or, :nor, :xor, :not]

  def unquote(:"is_valid")({name, module}) do
    valid_module =
      module.module_info[:attributes]
        |> Keyword.get(:behaviour, [])
        |> Enum.member?(LogicalPermissions.PermissionType)

    cond do
      valid_module == false -> {:error, "The module #{module} must adopt the LogicalPermissions.PermissionType behavior."}
      name in unquote(reserved_permission_keys) -> {:error, "The name of a permission type cannot be one of the following: #{inspect(unquote(reserved_permission_keys))}"}
      true -> {:ok, true}
    end
  end

  def unquote(:"get_reserved_permission_keys")() do
    unquote(reserved_permission_keys)
  end
end
