defmodule LogicalPermissions.PermissionTypeBuilder do
  require LogicalPermissions.Validator

  permission_types = Application.get_env(:logical_permissions, :permission_types, [])

  # Generate functions for each permission type
  Enum.each(permission_types, fn({name, module}) ->
    case LogicalPermissions.Validator.is_valid?({name, module}) do
      {:error, message} -> raise InvalidPermissionTypeError, message: "Error adding permission type #{inspect(name)}: #{inspect(message)}"
      {:ok, true} -> nil
    end

    # Generate a type_exists? function for this type
    def unquote(:"type_exists?")(unquote(name)) do
      true
    end
    # Generate a get_module function for this type
    def unquote(:"get_module")(unquote(name)) do
      {:ok, unquote(module)}
    end
  end)

  # Fallback type_exists? function that returns false for all types that haven't been registered
  @spec type_exists?(atom) :: Boolean.t
  def type_exists?(_) do
    false
  end

  # Fallback get_module function that returns a helpful error message for types that haven't been registered
  @spec get_module(atom) :: {:ok, Module.t,} | {:error, String.t}
  def get_module(permission_type) do
    {:error, "The permission type #{inspect(permission_type)} has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  # Generate a function that returns valid permission types
  def unquote(:"get_permission_types")() do
    unquote(permission_types)
  end
end
