defmodule LogicalPermissions.MixProject do
  use Mix.Project

  def project do
    [
      app: :logical_permissions,
      version: "0.4.0",
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      test_paths: test_paths(Mix.env()),
      description: description(),
      package: package(),
      deps: deps(),
      dialyzer: dialyzer(),
      source_url: "https://github.com/ordermind/logical-permissions-elixir"
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:logic_gates, "~> 0.6"},
      {:dialyxir, "~> 1.3", only: [:test], runtime: false}
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp package() do
    [
      name: "logical_permissions",
      # These are the default files included in the package
      files: ~w(lib mix.exs README* LICENSE*),
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/ordermind/logic-gates-elixir"}
    ]
  end

  defp description() do
    "Provides support for list/map-based permissions with logic gates such as AND and OR."
  end

  defp dialyzer() do
    [
      # Put the project-level PLT in the priv/ directory (instead of the default _build/ location)
      plt_file: {:no_warn, "priv/plts/project.plt"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/normal", "test/shared"]

  defp elixirc_paths(:test_invalid_bypass_access_checker),
    do: ["lib", "test/invalid_bypass_access_checker", "test/shared"]

  defp elixirc_paths(:test_no_bypass_access_checker),
    do: ["lib", "test/no_bypass_access_checker", "test/shared"]

  defp elixirc_paths(:test_compile_warnings), do: ["lib", "test/compile_warnings", "test/shared"]
  defp elixirc_paths(:dialyzer), do: ["lib", "test/shared/valid"]
  defp elixirc_paths(_), do: ["lib"]

  defp test_paths(:test), do: ["test/normal"]
  defp test_paths(:test_invalid_bypass_access_checker), do: ["test/invalid_bypass_access_checker"]
  defp test_paths(:test_no_bypass_access_checker), do: ["test/no_bypass_access_checker"]
  defp test_paths(:test_compile_warnings), do: ["test/compile_warnings"]
  defp test_paths(_), do: []
end
