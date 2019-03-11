use Mix.Config

config :logical_permissions, :bypass_access_checker, LogicalPermissions.Test.BypassAccessCheckerInvalidBehavior
config :logical_permissions, :permission_types, invalid_behavior: LogicalPermissions.Test.InvalidBehavior
config :logical_permissions, :permission_types, nor: LogicalPermissions.Test.InvalidName
