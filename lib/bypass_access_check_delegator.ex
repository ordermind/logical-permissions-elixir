defmodule LogicalPermissions.BypassAccessCheckDelegator do
  @moduledoc """
  Internal module used for delegating bypass access to a registered module.
  """

  alias LogicalPermissions.BypassAccessCheckerBuilder

  @doc """
  Calls the registered module for checking bypass access and returns the result.
  """
  @spec check_bypass_access(map()) :: {:ok, boolean()} | {:error, binary()}

  # Generate a function for checking access bypass if a bypass access checker is available, otherwise generate a fallback function
  case BypassAccessCheckerBuilder.get_module() do
    nil ->
      def unquote(:check_bypass_access)(_) do
        {:ok, false}
      end

    module ->
      def unquote(:check_bypass_access)(context) do
        case apply(unquote(module), :check_bypass_access, [context]) do
          {:ok, access} when is_boolean(access) ->
            {:ok, access}

          {:error, reason} when is_binary(reason) ->
            {:error, reason}

          result ->
            {:error,
             "An unexpected value was returned from #{unquote(module)}.check_bypass_access/1. Please refer to the behaviour to see what kind of values are valid. Received value: #{inspect(result)}"}
        end
      end
  end
end
