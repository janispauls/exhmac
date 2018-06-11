defmodule Exhmac.Mixfile do
  use Mix.Project

  def project do
    [app: :exhmac,
     version: "0.0.5",
     elixir: "~> 1.0",
     deps: deps()
    ]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [applications: [:logger, :timex, :tzdata]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type `mix help deps` for more examples and options
  defp deps do
    [
      {:timex, "3.1.13"},
      {:mock, github: "jjh42/mock", only: :test},
      {:dialyxir, "~> 0.5.0", only: [:dev, :test]},
      {:credo, "~> 0.5", only: [:dev, :test]}
    ]
  end
end
