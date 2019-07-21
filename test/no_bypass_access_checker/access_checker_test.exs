defmodule AccessCheckerTest do
  use ExUnit.Case
  doctest LogicalPermissions.AccessChecker

  test "check_access/1 no access bypass checker available" do
    assert LogicalPermissions.AccessChecker.check_access(false) == {:ok, false}
  end
end
