defmodule LogicalPermissions.AccessChecker do
  require LogicalPermissions.PermissionTypeBuilder
  require LogicalPermissions.BypassAccessCheckerBuilder
  require LogicalPermissions.Validator

  # Generate a function for checking permission for each permission type
  Enum.each(LogicalPermissions.PermissionTypeBuilder.get_permission_types(), fn {name, module} ->
    defp unquote(:"check_permission")(unquote(name), value, context) do
      apply(unquote(module), :check_permission, [value, context])
    end
  end)

  # Fallback check_permission() function that returns a helpful error message for types that haven't been registered
  @spec check_permission(atom, String.t, Tuple.t) :: {:ok, Boolean.t} | {:error, String.t}
  defp check_permission(permission_type_name, _, _) do
    {:error, "The permission type '#{permission_type_name}' has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  def unquote(:"get_valid_permission_keys")() do
    Enum.concat(unquote(LogicalPermissions.Validator.get_reserved_permission_keys), Keyword.keys(unquote(LogicalPermissions.PermissionTypeBuilder.get_permission_types)))
  end

  # Generate a function for checking access bypass if a bypass access checker is available, otherwise generate a fallback function
  case LogicalPermissions.BypassAccessCheckerBuilder.get_module do
  module ->
    defp unquote(:"check_bypass_access")(context) do
      apply(unquote(module), :check_bypass_access, [context])
    end
  nil ->
    defp unquote(:"check_bypass_access")(_) do
      {:ok, false}
    end
  end

  def check_access(permissions, context \\ {}, allow_bypass \\ true)
  def check_access(permissions, context, allow_bypass) when is_map(permissions) and is_tuple(context) and is_boolean(allow_bypass) do
    allow_bypass =
      cond do
        allow_bypass && Map.has_key?(permissions, :no_bypass) ->
          case Map.fetch(permissions, :no_bypass) do
            no_bypass when is_boolean(no_bypass) -> !no_bypass
            no_bypass when is_map(no_bypass) -> !process_or(no_bypass, context)
          end
        true ->
          allow_bypass
      end
    permissions = Map.drop(permissions, [:no_bypass])

    cond do
      allow_bypass && check_bypass_access(context) == {:ok, true} -> {:ok, true}
      Enum.count(permissions) == 0 -> {:ok, true}
      true -> process_or(permissions, context)
    end
  end
  def check_access(permissions, context, allow_bypass) when is_boolean(permissions) and is_tuple(context) and is_boolean(allow_bypass) do
    dispatch(permissions)
  end
  def check_access(_, _, _) do
    {:error, "The permissions parameter must be a map or a boolean."}
  end

  defp dispatch(permissions, context \\ {}, type \\ nil)
  defp dispatch(permissions, _, nil) when is_boolean(permissions) do
    {:ok, permissions}
  end
  defp dispatch(permissions, _, type) when is_boolean(permissions) do
    {:error, "You cannot put a boolean permission as a descendant to a permission type. Existing type: #{type}. Evaluated permissions: #{inspect(permissions)}"}
  end
  defp dispatch(permissions, context, type) when is_binary(permissions) do
    IO.inspect({permissions, type})
    check_permission(type, permissions, context)
  end
  defp dispatch({key, value}, context, type) do
    case key do
      :no_bypass -> {:error, "The :no_bypass key must be placed highest in the permission hierarchy. Evaluated permissions: #{inspect(%{key => value})}"}
      :and -> process_and(value, context, type)
      :nand -> process_nand(value, context, type)
      :or -> process_or(value, context, type)
      :nor -> process_nor(value, context, type)
      :xor -> process_xor(value, context, type)
      :not -> process_not(value, context, type)
      n when n in [true, false] -> {:error, "A boolean permission cannot have children. Evaluated permissions: #{inspect(%{key => value})}"}
      n when is_atom(n) ->
        cond do
          type ->
            {:error, "You cannot put a permission type as a descendant to another permission type. Existing type: #{type}. Evaluated permissions: #{inspect(%{key => value})}"}
          !LogicalPermissions.PermissionTypeBuilder.type_exists?(key) ->
            {:error, "The permission type '#{key}' has not been registered. Please refer to the documentation regarding how to register a permission type."}
          true ->
            case value do
              n when is_list(n) -> process_or(value, context, key)
              n when is_map(n) -> process_or(value, context, key)
              n when is_binary(n) -> dispatch(value, context, key)
              n when is_boolean(n) -> dispatch(value, context, key)
              _ -> {:error, "The permission value must be either a list, a map, a string or a boolean. Evaluated permissions: #{inspect(%{key => value})}"}
            end
        end
    end
  end

  defp process_and(permissions, context, type)
  defp process_and(permissions, _, _) when is_map(permissions) and map_size(permissions) < 1 do
    {:error, "The value map of an AND gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_and(permissions, context, type) when is_map(permissions) do
    process_and(Map.to_list(permissions), context, type)
  end
  defp process_and(permissions, _, _) when is_list(permissions) and length(permissions) < 1 do
    {:error, "The value list of an AND gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_and(permissions, context, type) when is_list(permissions) do
    Enum.reduce_while(permissions, nil, fn permission, _ ->
      case dispatch(permission, context, type) do
        {:ok, false} -> {:halt, {:ok, false}}
        {:error, reason} -> {:halt, {:error, reason}}
        _ -> {:cont, {:ok, true}}
      end
    end)
  end
  defp process_and(permissions, _, _) do
    {:error, "The value of an AND gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_nand(permissions, context, type)
  defp process_nand(permissions, _, _) when is_list(permissions) and length(permissions) < 1 do
    {:error, "The value list of a NAND gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_nand(permissions, _, _) when is_map(permissions) and map_size(permissions) < 1 do
    {:error, "The value map of a NAND gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_nand(permissions, context, type) when is_list(permissions) or is_map(permissions) do
    case process_and(permissions, context, type) do
      {:ok, value} -> {:ok, !value}
      {:error, reason} -> {:error, reason}
    end
  end
  defp process_nand(permissions, _, _) do
    {:error, "The value of a NAND gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_or(permissions, context, type \\ nil)
  defp process_or(permissions, _, _) when is_map(permissions) and map_size(permissions) < 1 do
    {:error, "The value map of an OR gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_or(permissions, context, type) when is_map(permissions) do
    process_or(Map.to_list(permissions), context, type)
  end
  defp process_or(permissions, _, _) when is_list(permissions) and length(permissions) < 1 do
    {:error, "The value list of an OR gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_or(permissions, context, type) when is_list(permissions) do
    Enum.reduce_while(permissions, nil, fn permission, _ ->
      case dispatch(permission, context, type) do
        {:ok, true} -> {:halt, {:ok, true}}
        {:error, reason} -> {:halt, {:error, reason}}
        _ -> {:cont, {:ok, false}}
      end
    end)
  end
  defp process_or(permissions, _, _) do
    {:error, "The value of an OR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_nor(permissions, context, type)
  defp process_nor(permissions, _, _) when is_list(permissions) and length(permissions) < 1 do
    {:error, "The value list of a NOR gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_nor(permissions, _, _) when is_map(permissions) and map_size(permissions) < 1 do
    {:error, "The value map of a NOR gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_nor(permissions, context, type) when is_list(permissions) or is_map(permissions) do
    case process_or(permissions, context, type) do
      {:ok, value} -> {:ok, !value}
      {:error, reason} -> {:error, reason}
    end
  end
  defp process_nor(permissions, _, _) do
    {:error, "The value of a NOR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_xor(permissions, context, type)
  defp process_xor(permissions, _, _) when is_map(permissions) and map_size(permissions) < 2 do
    {:error, "The value map of an XOR gate must contain a minimum of two elements. Current value: #{inspect(permissions)}"}
  end
  defp process_xor(permissions, context, type) when is_map(permissions) do
    process_xor(Map.to_list(permissions), context, type)
  end
  defp process_xor(permissions, _, _) when is_list(permissions) and length(permissions) < 2 do
    {:error, "The value list of an XOR gate must contain a minimum of two elements. Current value: #{inspect(permissions)}"}
  end
  defp process_xor(permissions, context, type) when is_list(permissions) do
    Enum.reduce_while(permissions, %{counters: %{true: 0, false: 0}, access: {:ok, false}}, fn permission, acc ->
      case dispatch(permission, context, type) do
        {:ok, true} ->
          case acc.counters.false do
            0 -> {:cont, %{counters: %{true: acc.counters.true + 1, false: acc.counters.false}, access: acc.access}}
            _ -> {:halt, %{counters: acc.counters, access: {:ok, true}}}
          end
        {:ok, false} ->
          case acc.counters.true do
            0 -> {:cont, %{counters: %{true: acc.counters.true, false: acc.counters.false + 1}, access: acc.access}}
            _ -> {:halt, %{counters: acc.counters, access: {:ok, true}}}
          end
        {:error, reason} ->
          {:halt, %{counters: acc.counters, access: {:error, reason}}}
      end
    end)
    |> Map.fetch!(:access)
  end
  defp process_xor(permissions, _, _) do
    {:error, "The value of an XOR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_not(permissions, context, type)
  defp process_not(permissions, _, _) when is_map(permissions) and map_size(permissions) != 1 do
    {:error, "The value map of a NOT gate must contain exactly one element. Current value: #{inspect(permissions)}"}
  end
  defp process_not(permissions, context, type) when is_map(permissions) do
    !dispatch(permissions, context, type)
  end
  defp process_not(permissions, _, _) when is_binary(permissions) and permissions == "" do
    {:error, "The value of a NOT gate cannot have an empty string as its value."}
  end
  defp process_not(permissions, context, type) when is_binary(permissions) do
    !dispatch(permissions, context, type)
  end
  defp process_not(permissions, _, _) do
    {:error, "The value of a NOT gate must either be a map or a string. Current value: #{inspect(permissions)}"}
  end
end
