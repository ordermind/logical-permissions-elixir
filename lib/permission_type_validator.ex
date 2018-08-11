defmodule LogicalPermissions.Validator do
  reserved_permission_keys = [:no_bypass, :and, :nand, :or, :nor, :xor, :not, :true, :false]

  def unquote(:"is_valid?")({name, module}) do
    # Validate module
    module.module_info[:attributes]
      |> Keyword.get(:behaviour, [])
      |> Enum.member?(LogicalPermissions.PermissionType)
      |> case do
        false ->
          {:error, "The module #{module} must adopt the LogicalPermissions.PermissionType behaviour."}
        true -> nil
        end

    # Validate name
    if name in unquote(reserved_permission_keys) do
      {:error, "The name of a permission type cannot be one of the following: #{inspect(unquote(reserved_permission_keys))}"}
    end

    {:ok, true}
  end

  def unquote(:"get_reserved_permission_keys")() do
    unquote(reserved_permission_keys)
  end
end
