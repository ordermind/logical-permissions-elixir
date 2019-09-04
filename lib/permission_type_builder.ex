defmodule LogicalPermissions.PermissionTypeBuilder do
  @moduledoc """
  Builds a list of permission types from configuration settings.
  """

  alias LogicalPermissions.PermissionTypeValidator

  permission_types = Application.get_env(:logical_permissions, :permission_types, [])

  # Generate functions for each valid permission type
  Enum.each(permission_types, fn {name, module} ->
    case PermissionTypeValidator.is_valid(name) do
      {:ok, true} ->
        @doc """
        Checks if a permission type has been registered.
        """
        @spec type_exists?(atom()) :: boolean()
        def unquote(:type_exists?)(unquote(name)) do
          true
        end

        @doc """
        Gets the registered module for a permission type.
        """
        @spec get_module(atom()) :: {:ok, module()} | {:error, binary()}
        def unquote(:get_module)(unquote(name)) do
          {:ok, unquote(module)}
        end

      {:error, message} ->
        IO.warn("Error adding permission type #{inspect(name)}: #{inspect(message)}")
    end
  end)

  # Fallback type_exists? function that returns false for all types that haven't been registered
  def type_exists?(_) do
    false
  end

  # Fallback get_module function that returns a helpful error message for types that haven't been registered
  def get_module(permission_type) do
    {:error,
     "The permission type #{inspect(permission_type)} has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  @doc """
  Gets all registered permission types.
  """
  @spec get_permission_types() :: list()
  def unquote(:get_permission_types)() do
    unquote(permission_types)
  end

  @doc """
  Gets a list of all valid keys that can be used in a permission tree.
  """
  @spec get_valid_permission_keys() :: list()
  def unquote(:get_valid_permission_keys)() do
    Enum.concat(
      unquote(PermissionTypeValidator.get_reserved_permission_keys()),
      Keyword.keys(unquote(permission_types))
    )
  end
end
