defmodule LogicalPermissions.BypassAccessCheckerBuilder do
  # Generate a function for checking access bypass, or a fallback function if no implementations were found
  case Application.get_env(:logical_permissions, :bypass_access_checker) do
    nil ->
      def unquote(:get_module)() do
        nil
      end

    module ->
      def unquote(:get_module)() do
        unquote(module)
      end
  end
end
