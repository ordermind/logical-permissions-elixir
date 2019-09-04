defmodule LogicalPermissions.PermissionCheckDelegator do
  @moduledoc """
  Internal module used for checking access for a certain permission.
  """

  alias LogicalPermissions.PermissionTypeBuilder

  @doc """
  Calls the registered module for a permission type and passes a value for access checking.
  """
  @spec check_permission(atom(), binary() | atom(), map()) ::
          {:ok, boolean()} | {:error, binary()}

  # Generate a function for checking permission for each permission type
  Enum.each(PermissionTypeBuilder.get_permission_types(), fn {name, module} ->
    def unquote(:check_permission)(unquote(name), value, context) do
      case apply(unquote(module), :check_permission, [value, context]) do
        {:ok, access} when is_boolean(access) ->
          {:ok, access}

        {:error, reason} when is_binary(reason) ->
          {:error, reason}

        result ->
          {:error,
           "An unexpected value was returned from #{unquote(module)}.check_permission/2. Please refer to the behaviour to see what kind of values are valid. Received value: #{
             inspect(result)
           }"}
      end
    end
  end)

  # Fallback check_permission() function that returns a helpful error message for types that haven't been registered
  def check_permission(permission_type_name, _, _) do
    {:error,
     "The permission type #{inspect(permission_type_name)} has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end
end
