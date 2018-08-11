defmodule LogicalPermissions.AccessChecker do
  require LogicalPermissions.PermissionTypeBuilder
  require LogicalPermissions.BypassAccessCheckerBuilder
  require LogicalPermissions.Validator

  # Generate a function for checking permission for each permission type
  Enum.each(LogicalPermissions.PermissionTypeBuilder.get_permission_types(), fn {name, module} ->
    defp unquote(:"check_permission?")(unquote(name), value, context) do
      apply(unquote(module), "check_permission?", [value, context])
    end
  end)

  # Fallback check_permission? function that returns a helpful error message for types that haven't been registered
  @spec check_permission?(atom, String.t, Tuple.t) :: {:ok, Boolean.t} | {:error, String.t}
  defp check_permission?(permission_type_name, _, _) do
    {:error, "The permission type '#{permission_type_name}' has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  def unquote(:"get_valid_permission_keys")() do
    Enum.concat(unquote(LogicalPermissions.Validator.get_reserved_permission_keys), Keyword.keys(unquote(LogicalPermissions.PermissionTypeBuilder.get_permission_types)))
  end

  # Generate a function for checking access bypass if a bypass access checker is available, otherwise generate a fallback function
  case LogicalPermissions.BypassAccessCheckerBuilder.get_module do
  module ->
    defp unquote(:"check_bypass_access?")(context) do
      apply(unquote(module), "check_bypass_access?", [context])
    end
  nil ->
    defp unquote(:"check_bypass_access?")(_) do
      {:ok, false}
    end
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
