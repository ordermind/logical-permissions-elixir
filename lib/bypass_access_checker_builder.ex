defmodule LogicalPermissions.BypassAccessCheckerBuilder do
  # Generate a function for checking permission bypass, or a fallback function if no implementations were found
  case Application.get_env(:logical_permissions, :bypass_access_checker) do
  module ->
    def unquote(:"get_module")() do
      unquote(module)
    end
  nil ->
    def unquote(:"get_module")() do
      :nil
    end
  end
end
