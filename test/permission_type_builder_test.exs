defmodule PermissionTypeBuilderTest do
  use ExUnit.Case
  doctest LogicalPermissions.PermissionTypeBuilder

  test "get_permission_types/0" do
    assert LogicalPermissions.PermissionTypeBuilder.get_permission_types == [flag: LogicalPermissions.Test.Flag, role: LogicalPermissions.Test.Role]
  end

  test "type_exists?/1" do
    assert LogicalPermissions.PermissionTypeBuilder.type_exists?(:role) == true
    assert LogicalPermissions.PermissionTypeBuilder.type_exists?("role") == false
    assert LogicalPermissions.PermissionTypeBuilder.type_exists?(:flag) == true
    assert LogicalPermissions.PermissionTypeBuilder.type_exists?("flag") == false
    assert LogicalPermissions.PermissionTypeBuilder.type_exists?(:unregistered) == false
  end

  test "get_permission_type_callback/1" do
    assert LogicalPermissions.PermissionTypeBuilder.get_module(:flag) == {:ok, LogicalPermissions.Test.Flag}
    assert LogicalPermissions.PermissionTypeBuilder.get_module(:role) == {:ok, LogicalPermissions.Test.Role}
    assert LogicalPermissions.PermissionTypeBuilder.get_module(:unregistered) == {:error, "The permission type 'unregistered' has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end
end
