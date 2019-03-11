defmodule LogicalPermissions.BypassAccessCheckerValidator do
  def unquote(:"is_valid")(module) do
    module.module_info[:attributes]
    |> Keyword.get(:behaviour, [])
    |> Enum.member?(LogicalPermissions.BypassAccessChecker)
    |> case do
        true -> {:ok, true}
        false -> {:error, "The module #{module} must adopt the LogicalPermissions.BypassAccessChecker behavior."}
      end
  end
end
