defmodule LogicalPermissions.MixProject do
  use Mix.Project

  def project do
    [
      app: :logical_permissions,
      version: "0.1.0",
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_paths: test_paths(Mix.env)
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
    ]
  end

  defp elixirc_paths(:test_normal), do: ["lib", "test/normal", "test/shared"]
  defp elixirc_paths(:test_no_bypass_access_checker), do: ["lib", "test/no_bypass_access_checker", "test/shared"]
  defp elixirc_paths(:test_compile_warnings), do: ["lib", "test/compile_warnings", "test/shared"]
  defp elixirc_paths(_), do: ["lib"]

  defp test_paths(:test_normal), do: ["test/normal"]
  defp test_paths(:test_no_bypass_access_checker), do: ["test/no_bypass_access_checker"]
  defp test_paths(:test_compile_warnings), do: ["test/compile_warnings"]
  defp test_paths(_), do: []
end
