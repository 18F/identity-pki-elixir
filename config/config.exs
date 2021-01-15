# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
use Mix.Config

config :identity_pki,
  ecto_repos: [IdentityPki.Repo]

# Configures the endpoint
config :identity_pki, IdentityPkiWeb.Endpoint,
  url: [host: "localhost"],
  secret_key_base: "QBjuPQFD2TKycy00UKWD661BfDinvIwNPB8ZciMODmC6h4sIsDeKnpcockEPWHAb",
  render_errors: [view: IdentityPkiWeb.ErrorView, accepts: ~w(html json), layout: false],
  pubsub_server: IdentityPki.PubSub,
  live_view: [signing_salt: "PaZAwe/f"]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{Mix.env()}.exs"
