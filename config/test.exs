use Mix.Config

config :logical_permissions, bypass_callback: {LogicalPermissions.Test.BypassAccess, :check_bypass_access?}
config :logical_permissions, permission_types: [flag: {LogicalPermissions.Test.Flag, :check_flag?}]
config :logical_permissions, permission_types: [role: {LogicalPermissions.Test.Role, :user_has_role?}]
