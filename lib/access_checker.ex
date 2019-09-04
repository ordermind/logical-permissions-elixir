defmodule LogicalPermissions.AccessChecker do
  @moduledoc """
  Main module used for checking access for a permission tree.
  """

  alias LogicalPermissions.BypassAccessCheckDelegator
  alias LogicalPermissions.PermissionCheckDelegator

  @doc """
  Checks access for a permission tree.
  """
  @spec check_access(nil | boolean() | map() | list(), map(), boolean()) ::
          {:ok, boolean()} | {:error, binary()}
  def check_access(permissions, context \\ %{}, allow_bypass \\ true)

  def check_access(_, context, _) when not is_map(context) do
    {:error, "The context parameter must be a map."}
  end

  def check_access(_, _, allow_bypass) when not is_boolean(allow_bypass) do
    {:error, "The allow_bypass parameter must be a boolean."}
  end

  def check_access(nil, context, allow_bypass) do
    check_access([], context, allow_bypass)
  end

  def check_access(permissions, context, allow_bypass) when is_map(permissions) do
    check_access(Map.to_list(permissions), context, allow_bypass)
  end

  def check_access(permissions, context, allow_bypass) when is_list(permissions) do
    no_bypass = check_no_bypass(permissions, context, allow_bypass)

    bypass_access =
      case no_bypass do
        {:ok, true} -> {:ok, false}
        {:ok, false} -> BypassAccessCheckDelegator.check_bypass_access(context)
        {:error, _} -> nil
      end

    # Delete all occurrences of :no_bypass in the first level of permissions
    permissions = permissions -- for {:no_bypass, value} <- permissions, do: {:no_bypass, value}

    cond do
      elem(no_bypass, 0) == :error ->
        {:error, "Error checking if bypassing access should be forbidden: #{elem(no_bypass, 1)}"}

      elem(bypass_access, 0) == :error ->
        {:error, "Error checking access bypass: #{elem(bypass_access, 1)}"}

      bypass_access == {:ok, true} ->
        {:ok, true}

      Enum.count(permissions) == 0 ->
        {:ok, true}

      true ->
        case dispatch(permissions, context, nil) do
          {:ok, access} -> {:ok, access}
          {:error, reason} -> {:error, "Error checking access: #{reason}"}
        end
    end
  end

  def check_access(permissions, context, allow_bypass) when is_boolean(permissions) do
    bypass_access =
      case allow_bypass do
        true -> BypassAccessCheckDelegator.check_bypass_access(context)
        false -> {:ok, false}
      end

    case bypass_access do
      {:ok, true} -> {:ok, true}
      # We don't bother to check for errors here because there is no chance of an error being returned.
      {:ok, false} -> dispatch(permissions, context, nil)
      {:error, reason} -> {:error, "Error checking access bypass: #{reason}"}
    end
  end

  def check_access(_, _, _) do
    {:error, "The permissions parameter must be either a list, a map or a boolean."}
  end

  defp check_no_bypass(permissions, context, allow_bypass) do
    case allow_bypass do
      false ->
        {:ok, true}

      true ->
        case Keyword.fetch(permissions, :no_bypass) do
          {:ok, no_bypass} ->
            cond do
              is_list(no_bypass) or is_map(no_bypass) or is_boolean(no_bypass) ->
                case dispatch(no_bypass, context, nil) do
                  {:ok, value} -> {:ok, value}
                  {:error, reason} -> {:error, reason}
                end

              true ->
                {:error,
                 "The no_bypass value must be either a list, a map or a boolean. Current value: #{
                   inspect(no_bypass)
                 }"}
            end

          :error ->
            {:ok, false}
        end
    end
  end

  @spec dispatch(list() | map() | binary() | atom() | boolean(), map(), atom() | nil) ::
          {:ok, boolean()} | {:error, binary()}
  defp dispatch(permissions, context, type)

  defp dispatch(permissions, _, nil) when is_boolean(permissions) do
    {:ok, permissions}
  end

  defp dispatch(permissions, _, type) when is_boolean(permissions) do
    {:error,
     "You cannot put a boolean permission as a descendant to a permission type. Existing type: #{
       inspect(type)
     }. Evaluated permissions: #{inspect(permissions)}"}
  end

  defp dispatch(permissions, _, nil) when is_binary(permissions) do
    {:error,
     "A permission check is attempted but no type has been supplied. Evaluated permissions: #{
       inspect(permissions)
     }"}
  end

  defp dispatch(permissions, context, type) when is_binary(permissions) do
    PermissionCheckDelegator.check_permission(type, permissions, context)
  end

  defp dispatch(permissions, context, type) when is_atom(permissions) do
    PermissionCheckDelegator.check_permission(type, permissions, context)
  end

  defp dispatch(permissions, context, type) when is_list(permissions) or is_map(permissions) do
    process_or(permissions, context, type)
  end

  defp dispatch({key, value}, context, type) do
    case key do
      :no_bypass ->
        {:error,
         "The :no_bypass key must be placed highest in the permission hierarchy. Evaluated permissions: #{
           inspect(%{key => value})
         }"}

      :and ->
        process_and(value, context, type)

      :nand ->
        process_nand(value, context, type)

      :or ->
        process_or(value, context, type)

      :nor ->
        process_nor(value, context, type)

      :xor ->
        process_xor(value, context, type)

      :not ->
        process_not(value, context, type)

      n when is_boolean(n) ->
        {:error,
         "A boolean permission cannot have children. Evaluated permissions: #{
           inspect(%{key => value})
         }"}

      n when is_integer(n) ->
        dispatch(value, context, type)

      n when is_atom(n) ->
        case type do
          nil ->
            case value do
              n when is_list(n) ->
                process_or(value, context, key)

              n when is_map(n) ->
                process_or(value, context, key)

              n when is_binary(n) ->
                dispatch(value, context, key)

              n when is_atom(n) ->
                dispatch(value, context, key)

              n when is_boolean(n) ->
                dispatch(value, context, key)

              _ ->
                {:error,
                 "The permission value must be either a list, a map, a string, an atom or a boolean. Evaluated permissions: #{
                   inspect(%{key => value})
                 }"}
            end

          _ ->
            {:error,
             "You cannot put a permission type as a descendant to another permission type. Existing type: #{
               inspect(type)
             }. Evaluated permissions: #{inspect(%{key => value})}"}
        end
    end
  end

  # AND processing
  defp process_and(permissions, context, type)

  defp process_and(permissions, context, type) when is_map(permissions) do
    process_and(Map.to_list(permissions), context, type)
  end

  defp process_and([h | t], context, type) do
    case dispatch(h, context, type) do
      {:ok, false} -> {:ok, false}
      {:error, reason} -> {:error, reason}
      _ -> process_and(t, context, type)
    end
  end

  defp process_and([], _, _) do
    {:ok, true}
  end

  defp process_and(permissions, _, _) do
    {:error,
     "The value of an AND gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  # NAND processing
  defp process_nand(permissions, context, type)

  defp process_nand(permissions, context, type)
       when is_list(permissions) or is_map(permissions) do
    case process_and(permissions, context, type) do
      {:ok, value} -> {:ok, !value}
      {:error, reason} -> {:error, reason}
    end
  end

  defp process_nand(permissions, _, _) do
    {:error,
     "The value of a NAND gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  # OR processing
  defp process_or(permissions, context, type)

  defp process_or(permissions, context, type) when is_map(permissions) do
    process_or(Map.to_list(permissions), context, type)
  end

  defp process_or([h | t], context, type) do
    case dispatch(h, context, type) do
      {:ok, true} -> {:ok, true}
      {:error, reason} -> {:error, reason}
      _ -> process_or(t, context, type)
    end
  end

  defp process_or([], _, _) do
    {:ok, false}
  end

  defp process_or(permissions, _, _) do
    {:error,
     "The value of an OR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  # NOR processing
  defp process_nor(permissions, context, type)

  defp process_nor(permissions, context, type) when is_list(permissions) or is_map(permissions) do
    case process_or(permissions, context, type) do
      {:ok, value} -> {:ok, !value}
      {:error, reason} -> {:error, reason}
    end
  end

  defp process_nor(permissions, _, _) do
    {:error,
     "The value of a NOR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  # XOR processing
  defp process_xor(permissions, context, type, counter \\ %{true: 0, false: 0})

  defp process_xor(permissions, context, type, _) when is_map(permissions) do
    process_xor(Map.to_list(permissions), context, type)
  end

  defp process_xor([h | t], context, type, counter) do
    case dispatch(h, context, type) do
      {:ok, true} ->
        case counter.false do
          0 -> process_xor(t, context, type, %{true: counter.true + 1, false: counter.false})
          _ -> {:ok, true}
        end

      {:ok, false} ->
        case counter.true do
          0 -> process_xor(t, context, type, %{true: counter.true, false: counter.false + 1})
          _ -> {:ok, true}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp process_xor([], _, _, _) do
    {:ok, false}
  end

  defp process_xor(permissions, _, _, _) do
    {:error,
     "The value of a XOR gate must be a list or a map. Current value: #{inspect(permissions)}"}
  end

  # NOT processing
  defp process_not(permissions, context, type)

  defp process_not(permissions, _, _) when is_list(permissions) and length(permissions) != 1 do
    {:error,
     "The value list of a NOT gate must contain exactly one element. Current value: #{
       inspect(permissions)
     }"}
  end

  defp process_not(permissions, _, _) when is_map(permissions) and map_size(permissions) != 1 do
    {:error,
     "The value map of a NOT gate must contain exactly one element. Current value: #{
       inspect(permissions)
     }"}
  end

  defp process_not(permissions, _, _) when is_binary(permissions) and permissions == "" do
    {:error, "The value of a NOT gate cannot be an empty string."}
  end

  defp process_not(permissions, context, type)
       when is_list(permissions) or is_map(permissions) or is_binary(permissions) or
              is_atom(permissions) do
    case dispatch(permissions, context, type) do
      {:ok, value} -> {:ok, !value}
      {:error, reason} -> {:error, reason}
    end
  end

  defp process_not(permissions, _, _) do
    {:error,
     "The value of a NOT gate must either be a list, a map, a string or an atom. Current value: #{
       inspect(permissions)
     }"}
  end
end
