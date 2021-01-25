use Mix.Config

# Configure your database
config :identity_pki, IdentityPki.Repo,
  database: "identity_pki_dev",
  hostname: "localhost",
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

# For development, we disable any cache and enable
# debugging and code reloading.
#
# The watchers configuration can be used to run external
# watchers to your application. For example, we use it
# with webpack to recompile .js and .css sources.
config :identity_pki, IdentityPkiWeb.Endpoint,
  http: [port: 4000],
  debug_errors: true,
  code_reloader: true,
  check_origin: false,
  watchers: []

config :identity_pki,
  token_encryption_key_salt:
    "23df6c812fb1ca9c17debee3a91aba30bc0e85c38b414ee59a9e3d3eb5ec5c0221e2558cac8a808375711cb1450a9db40b8aec74f147e4a3e15dc3c304f1b23e",
  token_encryption_key_pepper:
    "c6b4a68a3adf0ff2069d5240bb71532c7a8c0dbb77bba5f9070e2d8ab1ebcc918cc8d8cdbb04fa34ed71126fac3e02d9c85280ae0f7c42d22b678e3e5eb67cfe",
  verify_token_secret:
    "ee7f20f44cdc2ba0c6830f70470d1d1d059e1279cdb58134db92b35947b1528ef5525ece5910cf4f2321ab989a618feea12ef95711dbc62b9601e8520a34ee12"

# ## SSL Support
#
# In order to use HTTPS in development, a self-signed
# certificate can be generated by running the following
# Mix task:
#
#     mix phx.gen.cert
#
# Note that this task requires Erlang/OTP 20 or later.
# Run `mix help phx.gen.cert` for more information.
#
# The `http:` config above can be replaced with:
#
#     https: [
#       port: 4001,
#       cipher_suite: :strong,
#       keyfile: "priv/cert/selfsigned_key.pem",
#       certfile: "priv/cert/selfsigned.pem"
#     ],
#
# If desired, both `http:` and `https:` keys can be
# configured to run both http and https servers on
# different ports.

# Watch static and templates for browser reloading.
config :identity_pki, IdentityPkiWeb.Endpoint,
live_reload: [
  patterns: [
    ~r"priv/static/.*(js|css|png|jpeg|jpg|gif|svg)$",
    ~r"priv/gettext/.*(po)$",
    ~r"lib/identity_pki_web/(live|views)/.*(ex)$",
    ~r"lib/identity_pki_web/templates/.*(eex)$"
  ]
]

# Do not include metadata nor timestamps in development logs
config :logger, :console, format: "[$level] $message\n"

# Set a higher stacktrace during development. Avoid configuring such
# in production as building large stacktraces may be expensive.
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime
