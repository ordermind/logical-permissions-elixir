defmodule LogicalPermissions.BypassAccessCheckerBuilder do
  require LogicalPermissions.BypassAccessCheckerValidator

  # Generate a function for checking access bypass, or a fallback function if no implementations were found
  case Application.get_env(:logical_permissions, :bypass_access_checker) do
  nil ->
    def unquote(:get_module)() do
      nil
    end
  module ->
    case LogicalPermissions.BypassAccessCheckerValidator.is_valid(module) do
      {:ok, true} ->
        def unquote(:get_module)() do
          unquote(module)
        end
      {:error, reason} ->
        def unquote(:get_module)() do
          nil
        end
        IO.warn("Error adding access bypass checker: #{inspect(reason)}")
    end
  end
end
