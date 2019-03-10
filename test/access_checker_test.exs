defmodule AccessCheckerTest do
  use ExUnit.Case
  doctest LogicalPermissions.AccessChecker

  test "get_valid_permission_keys/0" do
    assert LogicalPermissions.AccessChecker.get_valid_permission_keys == [:no_bypass, :and, :nand, :or, :nor, :xor, :not, true, false, :flag, :role]
  end

  test "check_access/1 wrong permissions param type" do
    assert LogicalPermissions.AccessChecker.check_access(0) == {:error, "The permissions parameter must be a map or a boolean."}
  end

  test "check_access/3 wrong permission value type" do
    permissions = %{flag: 50}
    assert LogicalPermissions.AccessChecker.check_access(permissions, {}, false) == {:error, "The permission value must be either a list, a map, a string or a boolean. Evaluated permissions: #{inspect(permissions)}"}
  end

  test "check_access/3 nested permission types" do
    # Directly nested
    permissions = %{
      flag: %{
        flag: "testflag"
      }
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, {}, false) == {:error, "You cannot put a permission type as a descendant to another permission type. Existing type: flag. Evaluated permissions: %{flag: \"testflag\"}"}

    # Indirectly nested
    permissions = %{
      flag: %{
        or: %{
          flag: "testflag"
        }
      }
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, {}, false) == {:error, "You cannot put a permission type as a descendant to another permission type. Existing type: flag. Evaluated permissions: %{flag: \"testflag\"}"}
  end
end

