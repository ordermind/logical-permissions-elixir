defmodule LogicalPermissions.PermissionTypeValidator do
  reserved_permission_keys = [:no_bypass, :and, :nand, :or, :nor, :xor, :not]

  @doc """
  Checks whether a given permission key is valid.
  """
  @spec is_valid(atom()) :: {:ok, boolean()} | {:error, binary()}
  def is_valid(name)

  def unquote(:is_valid)(name) when is_atom(name) do
    case name in unquote(reserved_permission_keys) do
      true ->
        {:error,
         "The name of a permission type cannot be one of the following: #{
           inspect(unquote(reserved_permission_keys))
         }"}

      _ ->
        {:ok, true}
    end
  end

  def is_valid(_) do
    {:error, "The name of a permission type must be an atom."}
  end

  @doc """
  Gets the reserved permission keys that cannot be used as names of permission types.
  """
  @spec get_reserved_permission_keys() :: list()
  def unquote(:get_reserved_permission_keys)() do
    unquote(reserved_permission_keys)
  end
end
