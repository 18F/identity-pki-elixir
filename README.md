# IdentityPki

To start your Phoenix server:

  * Install dependencies with `mix deps.get`
  * Create and migrate your database with `mix ecto.setup`
  * Start Phoenix endpoint with `mix phx.server`

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.

Ready to run in production? Please [check our deployment guides](https://hexdocs.pm/phoenix/deployment.html).

## nginx

SSL is difficult, and we use nginx in the live environments so we use nginx in
development for the correct SSL client certificate behavior. The nginx
configuration template is partially copied from the configuration used in
deployed environments.

1. Generate self-signed certs with `mix phx.gen.cert`
2. Install nginx (`brew install nginx`)
3. Copy nginx config and edit the new file with your local paths: `cp priv/nginx/nginx_server.conf{.example,}`
4. Verify config and start nginx

Verify nginx:

```sh
# full path is needed
nginx -t -c /Users/USERNAME/projects/identity_pki/priv/nginx/nginx_server.conf
# syntax is ok
# nginx_server.conf test is successful
```

Start nginx:

```sh
# full path is needed
nginx -c /Users/USERNAME/projects/identity_pki/priv/nginx/nginx_server.conf
```
