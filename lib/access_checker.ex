defmodule LogicalPermissions.AccessChecker do
  require LogicalPermissions.PermissionTypeBuilder
  require LogicalPermissions.BypassAccessCheckerBuilder
  require LogicalPermissions.Validator

  # Generate a function for checking permission for each permission type
  Enum.each(LogicalPermissions.PermissionTypeBuilder.get_permission_types(), fn {name, module} ->
    defp unquote(:"check_permission")(unquote(name), value, context) do
      apply(unquote(module), "check_permission", [value, context])
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
      apply(unquote(module), "check_bypass_access", [context])
    end
  nil ->
    defp unquote(:"check_bypass_access")(_) do
      {:ok, false}
    end
  end

  def check_access(permissions, context \\ {}, allow_bypass \\ true)
  def check_access(permissions, context, allow_bypass) when is_map(permissions) and is_tuple(context) and is_boolean(allow_bypass) do
    allow_bypass =
      if Map.has_key?(permissions, :no_bypass) && allow_bypass do
        case Map.fetch(permissions, :no_bypass) do
          no_bypass when is_boolean(no_bypass) -> !no_bypass
          no_bypass when is_map(no_bypass) -> !process_or(no_bypass, nil, context)
        end
      else
        allow_bypass
      end
    permissions = Map.drop(permissions, :no_bypass)

    if allow_bypass && check_bypass_access(context) do
      {:ok, true}
    end
    if Enum.count(permissions) == 0 do
      {:ok, true}
    end
    process_or(permissions, nil, context)
  end
  def check_access(permissions, context, allow_bypass) when is_boolean(permissions) and is_tuple(context) and is_boolean(allow_bypass) do
    dispatch(permissions)
  end

  defp dispatch(permissions, context \\ {}, type \\ nil)
  defp dispatch(permissions, context, nil) when is_boolean(permissions) do
    {:ok, permissions}
  end
  defp dispatch(permissions, context, type) when is_boolean(permissions) do
    {:error, "You cannot put a boolean permission as a descendant to a permission type. Existing type: #{type}. Evaluated permissions: #{inspect(permissions)}"}
  end
  defp dispatch(permissions, context, type) when is_binary(permissions) do
    check_permission(type, permissions, context)
  end
  defp dispatch(permissions, context, type) when is_list(permissions) do
    process_or(permissions, context, type)
  end
  defp dispatch(permissions, context, type) when is_map(permissions) and map_size(permissions) > 1 do
    process_or(permissions, context, type)
  end
  defp dispatch(permissions, context, type) when is_map(permissions) and map_size(permissions) == 1 do
    {key, value} = permissions
      |> Map.to_list
      |> List.first
    case key do
      :no_bypass -> {:error, "The :no_bypass key must be placed highest in the permission hierarchy. Evaluated permissions: #{inspect(permissions)}"}
      :and -> process_and(permissions, context, type)
      :nand -> process_nand(permissions, context, type)
      :or -> process_or(permissions, context, type)
      :nor -> process_nor(permissions, context, type)
      :xor -> process_xor(permissions, context, type)
      :not -> process_not(permissions, context, type)
      n when n in [true, false] -> {:error, "A boolean permission cannot have children. Evaluated permissions: #{inspect(permissions)}"}
      n when is_atom(n) ->
        if type do
          {:error, "You cannot put a permission type as a descendant to another permission type. Existing type: #{type}. Evaluated permissions: #{inspect(permissions)}"}
        end
        if !LogicalPermissions.PermissionTypeBuilder.type_exists?(key) do
          {:error, "The permission type '#{key}' has not been registered. Please refer to the documentation regarding how to register a permission type."}
        end

        type = key

        case value do
          n when is_list(n) -> process_or(value, type, context)
          n when is_map(n) -> process_or(value, type, context)
          _ -> dispatch(value, type, context)
        end
    end
  end

  defp process_and(permissions, context, type \\ nil)
  defp process_and(permissions, context, type) when is_list(permissions) and length(permissions) < 1 do
    {:error, "The value list of an AND gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_and(permissions, context, type) when is_list(permissions) do
    Enum.each(permissions, fn permission ->
      case dispatch(permission, context, type) do
        {:ok, false} -> {:ok, false}
        {:error, reason} -> {:error, reason}
        _ -> nil
      end

      {:ok, true}
    end)
  end
  defp process_and(permissions, context, type) when is_map(permissions) and map_size(permissions) < 1 do
    {:error, "The value map of an AND gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_and(permissions, context, type) when is_map(permissions) do
    Enum.each(permissions, fn {key, value} ->
      case dispatch(%{key: value}, context, type) do
        {:ok, false} -> {:ok, false}
        {:error, reason} -> {:error, reason}
        _ -> nil
      end

      {:ok, true}
    end)
  end
  defp process_and(permissions, context, type) do
    {:error, "The value of an AND gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end


  defp process_nand(permissions, context, type \\ nil)
  defp process_nand(permissions, context, type) when is_list(permissions) and length(permissions) < 1 do
    {:error, "The value list of a NAND gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_nand(permissions, context, type) when is_map(permissions) and map_size(permissions) < 1 do
    {:error, "The value map of a NAND gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_nand(permissions, context, type) when is_list(permissions) or is_map(permissions) do
    case process_and(permissions, context, type) do
      {:ok, value} -> {:ok, !value}
      {:error, reason} -> {:error, reason}
    end
  end
  defp process_nand(permissions, context, type) do
    {:error, "The value of a NAND gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_or(permissions, context, type \\ nil)
  defp process_or(permissions, context, type) when is_list(permissions) and length(permissions) < 1 do
    {:error, "The value list of an OR gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_and(permissions, context, type) when is_list(permissions) do
    Enum.each(permissions, fn permission ->
      case dispatch(permission, context, type) do
        {:ok, true} -> {:ok, true}
        {:error, reason} -> {:error, reason}
        _ -> nil
      end

      {:ok, false}
    end)
  end
  defp process_or(permissions, context, type) when is_map(permissions) and map_size(permissions) < 1 do
    {:error, "The value map of an OR gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_or(permissions, context, type) when is_map(permissions) do
    Enum.each(permissions, fn {key, value} ->
      case dispatch(%{key: value}, context, type) do
        {:ok, true} -> {:ok, true}
        {:error, reason} -> {:error, reason}
        _ -> nil
      end

      {:ok, false}
    end)
  end
  defp process_or(permissions, context, type) do
    {:error, "The value of an OR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_nor(permissions, context, type \\ nil)
  defp process_nor(permissions, context, type) when is_list(permissions) and length(permissions) < 1 do
    {:error, "The value list of a NOR gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_nor(permissions, context, type) when is_map(permissions) and map_size(permissions) < 1 do
    {:error, "The value map of a NOR gate must contain a minimum of one element. Current value: #{inspect(permissions)}"}
  end
  defp process_nor(permissions, context, type) when is_list(permissions) or is_map(permissions) do
    case process_or(permissions, context, type) do
      {:ok, value} -> {:ok, !value}
      {:error, reason} -> {:error, reason}
    end
  end
  defp process_nor(permissions, context, type) do
    {:error, "The value of a NOR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_xor(permissions, context, type \\ nil)
  defp process_xor(permissions, context, type) when is_list(permissions) and length(permissions) < 2 do
    {:error, "The value list of an XOR gate must contain a minimum of two elements. Current value: #{inspect(permissions)}"}
  end
  defp process_xor(permissions, context, type) when is_list(permissions) do
    results = Enum.map(permissions, fn permission ->
      dispatch(permission, context, type)
    end)
    found_error = Enum.find(results, fn(element) ->
      match?({:error, reason}, element)
    end)
    if found_error do
      found_error
    end

    count = Enum.reduce(%{}, fn value, acc ->
      Map.update(acc, value, 1, &(&1 + 1))
    end)
    if Map.get(count, true) >= 1 and Map.get(count, false) >= 1 do
      {:ok, true}
    end

    {:ok, false}
  end
  defp process_xor(permissions, context, type) when is_map(permissions) and map_size(permissions) < 2 do
    {:error, "The value map of an XOR gate must contain a minimum of two elements. Current value: #{inspect(permissions)}"}
  end
  defp process_xor(permissions, context, type) when is_map(permissions) do
    results = Enum.map(permissions, fn {key, value} ->
      dispatch(%{key: value}, context, type)
    end)
    found_error = Enum.find(results, fn(element) ->
      match?({:error, reason}, element)
    end)
    if found_error do
      found_error
    end

    count = Enum.reduce(%{}, fn value, acc ->
      Map.update(acc, value, 1, &(&1 + 1))
    end)
    if Map.get(count, true) >= 1 and Map.get(count, false) >= 1 do
      {:ok, true}
    end

    {:ok, false}
  end
  defp process_xor(permissions, context, type) do
    {:error, "The value of an XOR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  defp process_not(permissions, context, type \\ nil)
  defp process_not(permissions, context, type) when is_map(permissions) and map_size(permissions) != 1 do
    {:error, "The value map of a NOT gate must contain exactly one element. Current value: #{inspect(permissions)}"}
  end
  defp process_not(permissions, context, type) when is_map(permissions) do
    !dispatch(permissions, context, type)
  end
  defp process_not(permissions, context, type) when is_binary(permissions) and permissions == "" do
    {:error, "The value of a NOT gate cannot have an empty string as its value."}
  end
  defp process_not(permissions, context, type) when is_binary(permissions) do
    !dispatch(permissions, context, type)
  end
  defp process_not(permissions, context, type) do
    {:error, "The value of a NOT gate must either be a map or a string. Current value: #{inspect(permissions)}"}
  end
end
