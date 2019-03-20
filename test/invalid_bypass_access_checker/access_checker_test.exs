defmodule AccessCheckerTest do
  use ExUnit.Case
  doctest LogicalPermissions.AccessChecker

  test "check_access/1 bypass access checker invalid return type" do
    assert LogicalPermissions.AccessChecker.check_access(false) == {:error, "Error checking access bypass: An unexpected value was returned from Elixir.LogicalPermissions.Test.BypassAccessCheckerInvalidReturnValue.check_bypass_access/1. Please refer to the behaviour to see what kind of values are valid. Received value: {:ok, \"invalid_return_value\"}"}
  end
end

