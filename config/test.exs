use Mix.Config

config :logical_permissions, :bypass_access_checker, LogicalPermissions.Test.BypassAccess
config :logical_permissions, :permission_types, flag: LogicalPermissions.Test.Flag
config :logical_permissions, :permission_types, role: LogicalPermissions.Test.Role
