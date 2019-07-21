defmodule BypassAccessCheckerBuilderTest do
  use ExUnit.Case
  doctest LogicalPermissions.BypassAccessCheckerBuilder

  test "get_module/0" do
    assert LogicalPermissions.BypassAccessCheckerBuilder.get_module() ==
             LogicalPermissions.Test.BypassAccessChecker
  end
end
