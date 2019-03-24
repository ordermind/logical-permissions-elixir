# :misc permission type

defmodule LogicalPermissions.Test.Misc do
  @behaviour LogicalPermissions.PermissionType

  # Permission type for testing various outcomes
  def check_permission(permission, _) do
    case permission do
      true -> {:ok, true}
      false -> {:ok, false}
      "error" -> {:error, "misc permission check error"}
    end
  end
end
