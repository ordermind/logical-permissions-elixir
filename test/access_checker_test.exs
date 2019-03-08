defmodule AccessCheckerTest do
  use ExUnit.Case
  doctest LogicalPermissions.AccessChecker

  test "get_valid_permission_keys/0" do
    assert LogicalPermissions.AccessChecker.get_valid_permission_keys == [:no_bypass, :and, :nand, :or, :nor, :xor, :not, true, false, :flag, :role]
  end

  test "check_access/0 wrong permissions param type" do
    assert LogicalPermissions.AccessChecker.check_access(0) == {:error, "The permissions parameter must be a map or a boolean."}
  end

  test "check_access/0 wrong permission value type" do
    assert LogicalPermissions.AccessChecker.check_access(%{flag: 50}) == {:error, "The permission value must be either a list, a map, a string or a boolean. Evaluated permissions: %{flag: 50}"}
  end
end

