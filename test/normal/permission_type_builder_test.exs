defmodule PermissionTypeBuilderTest do
  use ExUnit.Case
  doctest LogicalPermissions.PermissionTypeBuilder

  @permission_types [
    flag: LogicalPermissions.Test.Flag,
    role: LogicalPermissions.Test.Role,
    invalid_return_value: LogicalPermissions.Test.InvalidReturnValue,
    misc: LogicalPermissions.Test.Misc,
  ]

  test "get_permission_types/0" do
    assert LogicalPermissions.PermissionTypeBuilder.get_permission_types == @permission_types
  end

  test "type_exists?/1" do
    Enum.each(@permission_types, fn {name, _} ->
      assert LogicalPermissions.PermissionTypeBuilder.type_exists?(name) == true
      assert LogicalPermissions.PermissionTypeBuilder.type_exists?(Atom.to_string(name)) == false
    end)

    assert LogicalPermissions.PermissionTypeBuilder.type_exists?(:unregistered) == false
  end

  test "get_module/1" do
    Enum.each(@permission_types, fn {name, module} ->
      assert LogicalPermissions.PermissionTypeBuilder.get_module(name) == {:ok, module}
    end)

    assert LogicalPermissions.PermissionTypeBuilder.get_module(:unregistered) == {:error, "The permission type :unregistered has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end
end
