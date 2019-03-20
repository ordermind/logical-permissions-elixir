defmodule AccessCheckerTest do
  use ExUnit.Case
  doctest LogicalPermissions.AccessChecker

  test "get_valid_permission_keys/0" do
    assert LogicalPermissions.AccessChecker.get_valid_permission_keys == [:no_bypass, :and, :nand, :or, :nor, :xor, :not, :flag, :role, :invalid_return_value, :misc]
  end

  test "check_access/1 wrong permissions param type" do
    assert LogicalPermissions.AccessChecker.check_access(0) == {:error, "The permissions parameter must be either a list, a map or a boolean."}
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
    permissions = [
      flag: [
        or: [
          flag: "testflag"
        ]
      ]
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: You cannot put a permission type as a descendant to another permission type. Existing type: :flag. Evaluated permissions: %{flag: \"testflag\"}"}
  end

  test "check_access/3 unregistered type" do
    permissions = %{
      unregistered: "test"
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: The permission type :unregistered has not been registered. Please refer to the documentation regarding how to register a permission type."}
  end

  test "check_access/3 wrong allow_bypass param type" do
    assert LogicalPermissions.AccessChecker.check_access(false, %{}, "test") == {:error, "The allow_bypass parameter must be a boolean."}
  end

  test "check_access/2 bypass access list allow" do
    assert LogicalPermissions.AccessChecker.check_access([false], %{bypass_access: true}) == {:ok, true}
  end

  test "check_access/2 bypass access list deny" do
    assert LogicalPermissions.AccessChecker.check_access([false], %{bypass_access: false}) == {:ok, false}
  end

  test "check_access/3 bypass access list deny" do
    assert LogicalPermissions.AccessChecker.check_access([false], %{}, false) == {:ok, false}
  end

  test "check_access/2 bypass access boolean allow" do
    assert LogicalPermissions.AccessChecker.check_access(false, %{bypass_access: true}) == {:ok, true}
  end

  test "check_access/2 bypass access boolean deny" do
    assert LogicalPermissions.AccessChecker.check_access(false, %{bypass_access: false}) == {:ok, false}
  end

  test "check_access/3 bypass access boolean deny" do
    assert LogicalPermissions.AccessChecker.check_access(false, %{}, false) == {:ok, false}
  end

  test "check_access/2 bypass access error list permissions" do
    assert LogicalPermissions.AccessChecker.check_access([role: "admin"], 0) == {:error, "Error checking access bypass: The context parameter must be a map."}
  end

  test "check_access/2 bypass access error boolean permission" do
    assert LogicalPermissions.AccessChecker.check_access(false, 0) == {:error, "Error checking access bypass: The context parameter must be a map."}
  end

  test "check_access/1 no_bypass wrong type" do
    permissions = [
      false,
      no_bypass: "test"
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:error, "Error checking if bypassing access should be forbidden: The no_bypass value must be either a list, a map or a boolean. Current value: \"test\""}
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

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:error, "Error checking if bypassing access should be forbidden: An unexpected value was returned from Elixir.LogicalPermissions.Test.InvalidReturnValue.check_permission/3. Please refer to the behaviour to see what kind of values are valid. Received value: {:ok, \"invalid_return_value\"}"}
  end

  test "check_access/1 no_bypass empty permissions allow" do
    permissions = %{
      no_bypass: true
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:ok, true}
  end

  test "check_access/3 no_bypass mixed list types" do
    permissions = [
      false,
      no_bypass: [
        true,
      ],
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:ok, false}
  end

  test "check_access/2 no_bypass map allow" do
    user = %{
      id: 1,
      never_bypass: false
    }
    permissions = [
      false,
      no_bypass: %{
        flag: "never_bypass"
      }
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}) == {:ok, true}
  end

  test "check_access/2 no_bypass map deny" do
    user = %{
      id: 1,
      never_bypass: true
    }
    permissions = [
      false,
      no_bypass: %{
        flag: "never_bypass"
      }
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}) == {:ok, false}
  end

  test "check_access/2 no_bypass list allow" do
    user = %{
      id: 1,
      never_bypass: false
    }
    permissions = [
      false,
      no_bypass: [
        flag: "never_bypass"
      ]
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}) == {:ok, true}
  end

  test "check_access/2 no_bypass list deny" do
    user = %{
      id: 1,
      never_bypass: true
    }
    permissions = [
      false,
      no_bypass: [
        flag: "never_bypass"
      ]
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}) == {:ok, false}
  end

  test "check_access/1 no_bypass boolean allow" do
    permissions = [
      false,
      no_bypass: false
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:ok, true}
  end

  test "check_access/1 no_bypass boolean deny" do
    permissions = %{
      0 => false,
      no_bypass: true
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:ok, false}
  end

  test "check_access/3 multiple no_bypass boolean deny" do
    permissions = [
      false,
      no_bypass: true,
      no_bypass: false,
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions) == {:ok, false}
  end

  test "check_access/3 empty map allow" do
    assert LogicalPermissions.AccessChecker.check_access(%{}, %{}, false) == {:ok, true}
  end

  test "check_access/3 empty list allow" do
    assert LogicalPermissions.AccessChecker.check_access([], %{}, false) == {:ok, true}
  end

  test "check_access/3 single permission list error" do
    permissions = [misc: "error"]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: misc permission check error"}
  end

  test "check_access/3 single permission allow" do
    user = %{
      id: 1,
      testflag: true
    }
    permissions = %{
      flag: "testflag"
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 single permission deny" do
    user = %{
      id: 1
    }
    permissions = %{
      flag: "testflag"
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  #----Shorthand OR----#

  test "check_access/3 shorthand OR multiple types" do
    permissions = [
      flag: "testflag",
      role: "admin",
      flag: "test",
    ]

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

  test "check_access/3 shorthand OR multiple values" do
    permissions = [
      role: ["admin", "writer", "editor"]
    ]
    user = %{
      id: 1
    }

    # OR truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 0 1
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 0
    user = Map.put(user, :roles, ["writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 1
    user = Map.put(user, :roles, ["writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 0
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 1
    user = Map.put(user, :roles, ["admin", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 0
    user = Map.put(user, :roles, ["admin", "writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 1
    user = Map.put(user, :roles, ["admin", "writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  #----AND----#

  test "check_access/3 AND wrong value type" do
    permissions = [
      role: [
        and: "admin",
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value of an AND gate must be a list or a map. Current value: \"admin\""}
  end

  test "check_access/3 AND empty value" do
    permissions = [
      role: [
        and: [],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 AND multiple types" do
    permissions = [
      and: [
        flag: "testflag",
        role: "admin",
        flag: "test",
      ]
    ]

    user = %{
      id: 1,
    }

    # AND truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 0 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 1 0
    user = Map.put(user, :test, false)
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 1 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 0 0
    user = %{
      id: 1,
      testflag: true
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 0 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 1 0
    user = Map.put(user, :test, false)
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 1 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 AND multiple values" do
    permissions = [
      role: [
        and: ["admin", "writer", "editor"],
      ],
    ]
    user = %{
      id: 1
    }

    # AND truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 0 1
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 1 0
    user = Map.put(user, :roles, ["writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 1 1
    user = Map.put(user, :roles, ["writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 0 0
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 0 1
    user = Map.put(user, :roles, ["admin", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 1 0
    user = Map.put(user, :roles, ["admin", "writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 1 1
    user = Map.put(user, :roles, ["admin", "writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  #----NAND----#
  test "check_access/3 NAND wrong value type" do
    permissions = [
      role: [
        nand: "admin",
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value of a NAND gate must be a list or a map. Current value: \"admin\""}
  end

  test "check_access/3 NAND empty value" do
    permissions = [
      role: [
        nand: [],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  test "check_access/3 NAND multiple types" do
    permissions = [
      nand: [
        flag: "testflag",
        role: "admin",
        flag: "test",
      ]
    ]

    user = %{
      id: 1,
    }

    # NAND truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
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
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  test "check_access/3 NAND multiple values" do
    permissions = [
      role: [
        nand: ["admin", "writer", "editor"],
      ],
    ]
    user = %{
      id: 1
    }

    # NAND truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 0 1
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 0
    user = Map.put(user, :roles, ["writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 1
    user = Map.put(user, :roles, ["writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 0
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 1
    user = Map.put(user, :roles, ["admin", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 0
    user = Map.put(user, :roles, ["admin", "writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 1
    user = Map.put(user, :roles, ["admin", "writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  #----OR----#

  test "check_access/3 OR wrong value type" do
    permissions = [
      role: [
        or: "admin",
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value of an OR gate must be a list or a map. Current value: \"admin\""}
  end

  test "check_access/3 OR empty value" do
    permissions = [
      role: [
        or: [],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  test "check_access/3 OR multiple types" do
    permissions = [
      or: [
        flag: "testflag",
        role: "admin",
        flag: "test",
      ],
    ]

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

  test "check_access/3 OR multiple values" do
    permissions = [
      role: [
        or: ["admin", "writer", "editor"],
      ],
    ]
    user = %{
      id: 1
    }

    # OR truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 0 1
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 0
    user = Map.put(user, :roles, ["writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 1
    user = Map.put(user, :roles, ["writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 0
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 1
    user = Map.put(user, :roles, ["admin", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 0
    user = Map.put(user, :roles, ["admin", "writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 1
    user = Map.put(user, :roles, ["admin", "writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  #----NOR----#
  test "check_access/3 NOR wrong value type" do
    permissions = [
      role: [
        nor: "admin",
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value of a NOR gate must be a list or a map. Current value: \"admin\""}
  end

  test "check_access/3 NOR empty value" do
    permissions = [
      role: [
        nor: [],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 NOR multiple types" do
    permissions = [
      nor: [
        flag: "testflag",
        role: "admin",
        flag: "test",
      ],
    ]

    user = %{
      id: 1,
    }

    # NOR truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 0 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 1 0
    user = Map.put(user, :test, false)
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 1 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 0 0
    user = %{
      id: 1,
      testflag: true
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 0 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 1 0
    user = Map.put(user, :test, false)
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 1 1
    user = Map.put(user, :test, true)
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  test "check_access/3 NOR multiple values" do
    permissions = [
      role: [
        nor: ["admin", "writer", "editor"],
      ],
    ]
    user = %{
      id: 1
    }

    # NOR truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 0 1
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 1 0
    user = Map.put(user, :roles, ["writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 1 1
    user = Map.put(user, :roles, ["writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 0 0
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 0 1
    user = Map.put(user, :roles, ["admin", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 1 0
    user = Map.put(user, :roles, ["admin", "writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 1 1 1
    user = Map.put(user, :roles, ["admin", "writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  #----XOR----#
  test "check_access/3 XOR wrong value type" do
    permissions = [
      role: [
        xor: "admin",
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value of a XOR gate must be a list or a map. Current value: \"admin\""}
  end

  test "check_access/3 XOR empty value" do
    permissions = [
      role: [
        xor: [],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  test "check_access/3 XOR multiple types" do
    permissions = [
      xor: [
        flag: "testflag",
        role: "admin",
        flag: "test",
      ],
    ]

    user = %{
      id: 1,
    }

    # XOR truth table
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
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  test "check_access/3 XOR multiple values" do
    permissions = [
      role: [
        xor: ["admin", "writer", "editor"],
      ],
    ]
    user = %{
      id: 1
    }

    # XOR truth table
    # 0 0 0
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    # 0 0 1
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 0
    user = Map.put(user, :roles, ["writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 0 1 1
    user = Map.put(user, :roles, ["writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 0
    user = Map.put(user, :roles, ["admin"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 0 1
    user = Map.put(user, :roles, ["admin", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 0
    user = Map.put(user, :roles, ["admin", "writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    # 1 1 1
    user = Map.put(user, :roles, ["admin", "writer", "editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
  end

  #----NOT----#
  test "check_access/3 NOT wrong value type" do
    permissions = [
      role: [
        not: true,
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value of a NOT gate must either be a list, a map or a string. Current value: true"}
  end

  test "check_access/3 NOT map too few elements" do
    permissions = [
      role: [
        not: %{},
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value map of a NOT gate must contain exactly one element. Current value: %{}"}
  end

  test "check_access/3 NOT map too many elements" do
    permissions = [
      role: [
        not: %{
          0 => "admin",
          1 => "writer",
        },
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value map of a NOT gate must contain exactly one element. Current value: %{0 => \"admin\", 1 => \"writer\"}"}
  end

  test "check_access/3 NOT list too few elements" do
    permissions = [
      role: [
        not: [],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value list of a NOT gate must contain exactly one element. Current value: []"}
  end

  test "check_access/3 NOT list too many elements" do
    permissions = [
      role: [
        not: [
            "admin",
            "writer",
        ],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value list of a NOT gate must contain exactly one element. Current value: [\"admin\", \"writer\"]"}
  end

  test "check_access/3 NOT string empty" do
    permissions = [
      role: [
        not: ""
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:error, "Error checking access: The value of a NOT gate cannot be an empty string."}
  end

  test "check_access/3 NOT string" do
    permissions = [
      role: [
        not: "admin"
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin", "editor"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.drop(user, [:roles])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 NOT list" do
    permissions = [
      role: [
        not: [
          "admin",
        ],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin", "editor"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.drop(user, [:roles])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 NOT map" do
    permissions = [
      role: [
        not: %{
          0 => "admin",
        },
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin", "editor"],
    }

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, [])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.drop(user, [:roles])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 bool illegal children" do
    permissions = [
      true: false
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: A boolean permission cannot have children. Evaluated permissions: %{true: false}"}
  end

  test "check_access/3 bool TRUE illegal descendant" do
    permissions = [
      role: [true]
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: You cannot put a boolean permission as a descendant to a permission type. Existing type: :role. Evaluated permissions: true"}
  end

  test "check_access/3 bool TRUE" do
    permissions = [
      true
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:ok, true}
  end

  test "check_access/3 bool TRUE list" do
    permissions = [
      [true]
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:ok, true}
  end

  test "check_access/3 bool FALSE illegal descendant" do
    permissions = [
      role: [false]
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:error, "Error checking access: You cannot put a boolean permission as a descendant to a permission type. Existing type: :role. Evaluated permissions: false"}
  end

  test "check_access/3 bool FALSE" do
    permissions = [
      false
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:ok, false}
  end

  test "check_access/3 bool FALSE list" do
    permissions = [
      [false]
    ]

    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:ok, false}
  end

  test "check_access/3 mixed booleans" do
    permissions = [
      true,
      false,
    ]
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:ok, true}

    permissions = [
      or: [
        true,
        false,
      ]
    ]
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:ok, true}

    permissions = [
      and: [
        true,
        false,
      ]
    ]
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{}, false) == {:ok, false}
  end

  test "check_access/3 nested logic" do
    permissions = [
      false,
      role: [
        or: [
          not: [
            and: [
              "admin",
              "editor",
            ],
          ],
        ],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin", "editor"],
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = %{
      id: 1,
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 logic gate first" do
    permissions = [
      and: [
        true,
        and: [
          role: [
            or: [
              not: [
                and: [
                  "admin",
                  "editor",
                ],
              ],
            ],
          ],
        ],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin", "editor"],
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = %{
      id: 1,
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end

  test "check_access/3 shorthand OR mixed numeric and atom keys" do
    permissions = [
      role: [
        "admin",
        and: [
          "editor",
          "writer",
          or: [
            "role1",
            "role2",
          ],
        ],
      ],
    ]

    user = %{
      id: 1,
      roles: ["admin"],
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = %{
      id: 1,
    }
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, ["editor"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, ["editor", "writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, false}
    user = Map.put(user, :roles, ["editor", "writer", "role1"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, ["editor", "writer", "role2"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
    user = Map.put(user, :roles, ["admin", "writer"])
    assert LogicalPermissions.AccessChecker.check_access(permissions, %{user: user}, false) == {:ok, true}
  end
end

