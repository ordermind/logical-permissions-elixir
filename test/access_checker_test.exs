defmodule AccessCheckerTest do
  use ExUnit.Case
  doctest LogicalPermissions.AccessChecker

  test "get_valid_permission_keys/0" do
    assert LogicalPermissions.AccessChecker.get_valid_permission_keys == [:no_bypass, :and, :nand, :or, :nor, :xor, :not, true, false, :flag, :role]
  end
end

