defmodule AccessCheckerTest do
  use ExUnit.Case
  doctest LogicalPermissions.AccessChecker

  test "get_valid_permission_keys/0" do
    assert LogicalPermissions.AccessChecker.get_valid_permission_keys == [:no_bypass, :and, :nand, :or, :nor, :xor, :not, true, false, :flag, :role, :invalid_return_value, :misc]
  end

  test "check_access/1 wrong permissions param type" do
    assert LogicalPermissions.AccessChecker.check_access(0) == {:error, "The permissions parameter must be a map or a boolean."}
  end

  test "check_access/3 wrong permission value type" do
    permissions = %{flag: 50}

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: The permission value must be either a list, a map, a string or a boolean. Evaluated permissions: %{flag: 50}"}
  end

  test "check_access/3 nested permission types" do
    # Directly nested
    permissions = %{
      flag: %{
        flag: "testflag"
      }
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: You cannot put a permission type as a descendant to another permission type. Existing type: :flag. Evaluated permissions: %{flag: \"testflag\"}"}

    # Indirectly nested
    permissions = %{
      flag: %{
        or: %{
          flag: "testflag"
        }
      }
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: You cannot put a permission type as a descendant to another permission type. Existing type: :flag. Evaluated permissions: %{flag: \"testflag\"}"}
  end

  test "check_access/3 unregistered type" do
    permissions = %{
      unregistered: "test"
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: The permission type :unregistered has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  test "check_access/2 wrong context param type" do
    assert LogicalPermissions.AccessChecker.check_access(false, 0) == {:error, "The context parameter must be a map."}
  end

  test "check_access/3 wrong allow_bypass param type" do
    assert LogicalPermissions.AccessChecker.check_access(false, %{}, "test") == {:error, "The allow_bypass parameter must be a boolean."}
  end

  test "check_access/3 empty map allow" do
    assert LogicalPermissions.AccessChecker.check_access(%{}, %{}, false) == {:ok, true}
  end

  test "check_access/2 bypass access allow" do
    assert LogicalPermissions.AccessChecker.check_access(false, %{bypass_access: true}) == {:ok, true}
  end

  test "check_access/2 bypass access deny" do
    assert LogicalPermissions.AccessChecker.check_access(false, %{bypass_access: false}) == {:ok, false}
  end

  test "check_access/3 bypass access deny" do
    assert LogicalPermissions.AccessChecker.check_access(false, %{}, false) == {:ok, false}
  end

  test "check_access/1 no_bypass wrong type" do
    permissions = %{
      0 => false,
      no_bypass: "test"
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:error, "Error checking if bypassing access should be forbidden: The no_bypass value must be either a boolean or a map. Current value: \"test\""}
  end

  test "check_access/3 no_bypass illegal descendant" do
    permissions = %{
      or: %{
        no_bypass: true
      }
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: The :no_bypass key must be placed highest in the permission hierarchy. Evaluated permissions: %{no_bypass: true}"}
  end

  test "check_access/1 no_bypass wrong return type" do
    permissions = %{
      no_bypass: %{
        invalid_return_value: "never_bypass"
      },
      invalid_return_value: "test"
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:error, "Error checking if bypassing access should be forbidden: An unexpected value was returned from Elixir.LogicalPermissions.Test.InvalidReturnValue.check_permission/2. Please refer to the behavior to see what kind of values are valid. Received value: {:ok, \"invalid_return_value\"}"}
  end

  test "check_access/1 no_bypass empty permissions allow" do
    permissions = %{
      no_bypass: true
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:ok, true}
  end

  test "check_access/1 no_bypass boolean allow" do
    permissions = %{
      0 => false,
      no_bypass: false
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:ok, true}
  end

  test "check_access/1 no_bypass boolean deny" do
    permissions = %{
      0 => false,
      no_bypass: true
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:ok, false}
  end

  test "check_access/2 no_bypass map allow" do
    user = %{
      id: 1,
      never_bypass: false
    }
    permissions = %{
      0 => false,
      no_bypass: %{
        flag: "never_bypass"
      }
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}) == {:ok, true}
  end

  test "check_access/2 no_bypass map deny" do
    user = %{
      id: 1,
      never_bypass: true
    }
    permissions = %{
      0 => false,
      no_bypass: %{
        flag: "never_bypass"
      }
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}) == {:ok, false}
  end

  test "check_access/3 test single permission allow" do
    user = %{
      id: 1,
      testflag: true
    }
    permissions = %{
      flag: "testflag"
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 test single permission deny" do
    user = %{
      id: 1
    }
    permissions = %{
      flag: "testflag"
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  test "check_access/3 test access multiple types shorthand OR" do
    permissions = %{
      flag: "testflag",
      role: "admin",
      misc: "test",
    }

    user = %{
      id: 1,
    }

    # OR truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 0 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 0
    user = Map.put(user, :test, false)
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 0
    user = %{
      id: 1,
      testflag: true
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 0
    user = Map.put(user, :test, false)
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end
end

