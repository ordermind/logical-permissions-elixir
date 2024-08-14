import Config

config :logical_permissions, :bypass_access_checker, LogicalPermissions.Test.BypassAccessChecker
config :logical_permissions, :permission_types, flag: LogicalPermissions.Test.Flag
config :logical_permissions, :permission_types, role: LogicalPermissions.Test.Role

config :logical_permissions, :permission_types,
  invalid_return_value: LogicalPermissions.Test.InvalidReturnValue

config :logical_permissions, :permission_types, misc: LogicalPermissions.Test.Misc
