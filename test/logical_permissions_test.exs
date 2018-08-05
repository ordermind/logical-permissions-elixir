defmodule LogicalPermissionsTest do
  use ExUnit.Case
  doctest LogicalPermissions

  test "get_permission_types/0" do
    assert LogicalPermissions.get_permission_types == [flag: {LogicalPermissions.Test.Flag, :check_flag?}, role: {LogicalPermissions.Test.Role, :user_has_role?}]
  end

  test "type_exists?/1" do
    assert LogicalPermissions.type_exists?(:role) == true
    assert LogicalPermissions.type_exists?("role") == false
    assert LogicalPermissions.type_exists?(:flag) == true
    assert LogicalPermissions.type_exists?("flag") == false
    assert LogicalPermissions.type_exists?(:unregistered) == false
  end

  test "get_permission_type_callback/1" do
    assert LogicalPermissions.get_permission_type_callback(:flag) == {:ok, {LogicalPermissions.Test.Flag, :check_flag?}}
    assert LogicalPermissions.get_permission_type_callback(:role) == {:ok, {LogicalPermissions.Test.Role, :user_has_role?}}
    assert LogicalPermissions.get_permission_type_callback(:unregistered) == {:error, "The permission type 'unregistered' has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  test "get_bypass_callback/0" do
    assert LogicalPermissions.get_bypass_callback == {LogicalPermissions.Test.BypassAccess, :check_bypass_access?}
  end

  test "get_valid_permission_keys/0" do
    assert LogicalPermissions.get_valid_permission_keys == [:no_bypass, :and, :nand, :or, :nor, :xor, :not, true, false, :flag, :role]
  end

end
