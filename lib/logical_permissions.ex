defmodule LogicalPermissions do
  # Generate functions for each permission type
  permission_types = Application.get_env(:logical_permissions, :permission_types, [])
  Enum.each(permission_types, fn {permission_type, {module, function}} ->
    # Generate a function for checking permission for this type
    def unquote(:"check_permission?")(unquote(permission_type), value, context) do
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
  end)

  # Generate a function that returns valid permission types
  def unquote(:"get_permission_types")() do
    unquote(permission_types)
  end

  # Generate a function for checking permission bypass, or a fallback function if no implementations were found
  case Application.get_env(:logical_permissions, :bypass_callback) do
  {module, function} ->
    def unquote(:"check_bypass_access?")(context) do
      apply(unquote(module), unquote(function), [context])
    end
    def unquote(:"get_bypass_callback")() do
      {unquote(module), unquote(function)}
    end
  nil ->
    def unquote(:"check_bypass_access?")(_) do
      {:ok, false}
    end
    def unquote(:"get_bypass_callback")() do
      :nil
    end
  end

  # Fallback get_permission_type_callback function that returns a helpful error message for types that haven't been registered
  @spec get_permission_type_callback(atom) :: {:ok, {Module.t, Function.t}} | {:error, String.t}
  def get_permission_type_callback(permission_type) do
    {:error, "The permission type '#{permission_type}' has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  # Fallback check_permission? function that returns a helpful error message for types that haven't been registered
  @spec check_permission?(atom, String.t, Tuple.t) :: {:ok, Boolean.t} | {:error, String.t}
  def check_permission?(permission_type, _, _) do
    {:error, "The permission type '#{permission_type}' has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  # Fallback type_exists? function that returns false for all types that haven't been registered
  @spec type_exists?(atom) :: Boolean.t
  def type_exists?(_) do
    false
  end
end
