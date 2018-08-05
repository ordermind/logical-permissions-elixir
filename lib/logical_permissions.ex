defmodule LogicalPermissions do
  # Generate functions for each permission type
  core_permission_keys = [:no_bypass, :and, :nand, :or, :nor, :xor, :not, :true, :false]
  permission_types = Application.get_env(:logical_permissions, :permission_types, [])
  Enum.each(permission_types, fn {permission_type, {module, function}} ->
    # Validate permission type
    if permission_type in core_permission_keys do
      raise InvalidPermissionTypeError, message: "Error adding permission type '#{permission_type}': A permission type cannot be one of the following: #{inspect(core_permission_keys)}"
    else
      # Generate a function for checking permission for this type
      defp unquote(:"check_permission?")(unquote(permission_type), value, context) do
        apply(unquote(module), unquote(function), [value, context])
      end
      # Generate a type_exists? function for this type
      def unquote(:"type_exists?")(unquote(permission_type)) do
        true
      end
      # Generate a get_type_module function for this type
      def unquote(:"get_permission_type_callback")(unquote(permission_type)) do
        {:ok, {unquote(module), unquote(function)}}
      end
    end
  end)

  # Generate a function that returns valid permission types
  def unquote(:"get_permission_types")() do
    unquote(permission_types)
  end

  # Generate a function for checking permission bypass, or a fallback function if no implementations were found
  case Application.get_env(:logical_permissions, :bypass_callback) do
  {module, function} ->
    defp unquote(:"check_bypass_access?")(context) do
      apply(unquote(module), unquote(function), [context])
    end
    def unquote(:"get_bypass_callback")() do
      {unquote(module), unquote(function)}
    end
  nil ->
    defp unquote(:"check_bypass_access?")(_) do
      {:ok, false}
    end
    def unquote(:"get_bypass_callback")() do
      :nil
    end
  end

  defp unquote(:"get_core_permission_keys")() do
    unquote(core_permission_keys)
  end

  def unquote(:"get_valid_permission_keys")() do
    Enum.concat(unquote(core_permission_keys), Keyword.keys(unquote(permission_types)))
  end

  # Fallback get_permission_type_callback function that returns a helpful error message for types that haven't been registered
  @spec get_permission_type_callback(atom) :: {:ok, {Module.t, Function.t}} | {:error, String.t}
  def get_permission_type_callback(permission_type) do
    {:error, "The permission type '#{permission_type}' has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  # Fallback check_permission? function that returns a helpful error message for types that haven't been registered
  @spec check_permission?(atom, String.t, Tuple.t) :: {:ok, Boolean.t} | {:error, String.t}
  defp check_permission?(permission_type, _, _) do
    {:error, "The permission type '#{permission_type}' has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  # Fallback type_exists? function that returns false for all types that haven't been registered
  @spec type_exists?(atom) :: Boolean.t
  def type_exists?(_) do
    false
  end

  def check_access?(permissions, context \\ {}, allow_bypass \\ true)
  def check_access?(permissions, context, allow_bypass) when is_map(permissions) and is_tuple(context) and is_boolean(allow_bypass) do
    allow_bypass =
      if Map.has_key?(permissions, :no_bypass) && allow_bypass do
        case Map.fetch(permissions, :no_bypass) do
          no_bypass when is_boolean(no_bypass) -> !no_bypass
          no_bypass when is_map(no_bypass) -> !process_or?(no_bypass, nil, context)
        end
      else
        allow_bypass
      end
    permissions = Map.drop(permissions, :no_bypass)

    if allow_bypass && check_bypass_access?(context) do
      {:ok, true}
    end
    if Enum.count(permissions) == 0 do
      {:ok, true}
    end
    process_or?(permissions, nil, context)
  end
  def check_access?(permissions, context, allow_bypass) when is_binary(permissions) and is_tuple(context) and is_boolean(allow_bypass) do
    dispatch?(permissions)
  end
  def check_access?(permissions, context, allow_bypass) when is_boolean(permissions) and is_tuple(context) and is_boolean(allow_bypass) do
    dispatch?(permissions)
  end

  defp dispatch?(permissions, type \\ nil, context \\ {}) do
    {:ok, true}
  end

  def process_or?(permissions, type \\ nil, context) do
    {:ok, true}
  end
end
