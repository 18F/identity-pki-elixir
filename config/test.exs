use Mix.Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :identity_pki, IdentityPki.Repo,
  database: "identity_pki_test#{System.get_env("MIX_TEST_PARTITION")}",
  hostname: "localhost",
  pool: Ecto.Adapters.SQL.Sandbox

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :identity_pki, IdentityPkiWeb.Endpoint,
  http: [port: 4002],
  server: false

config :identity_pki,
  token_encryption_key_salt:
    "23df6c812fb1ca9c17debee3a91aba30bc0e85c38b414ee59a9e3d3eb5ec5c0221e2558cac8a808375711cb1450a9db40b8aec74f147e4a3e15dc3c304f1b23e",
  token_encryption_key_pepper:
    "c6b4a68a3adf0ff2069d5240bb71532c7a8c0dbb77bba5f9070e2d8ab1ebcc918cc8d8cdbb04fa34ed71126fac3e02d9c85280ae0f7c42d22b678e3e5eb67cfe",
  verify_token_secret:
    "ee7f20f44cdc2ba0c6830f70470d1d1d059e1279cdb58134db92b35947b1528ef5525ece5910cf4f2321ab989a618feea12ef95711dbc62b9601e8520a34ee12"

# Print only warnings and errors during test
config :logger, level: :warn
