# IdentityPki

To start your Phoenix server:

  * Install dependencies with `mix deps.get`
  * Create and migrate your database with `mix ecto.setup`
  * Start Phoenix endpoint with `mix phx.server`

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.

Ready to run in production? Please [check our deployment guides](https://hexdocs.pm/phoenix/deployment.html).

## nginx

1. Generate self-signed certs with `mix phx.gen.cert`
2. Install nginx
3. Edit `priv/nginx/nginx_server.conf` so the absolute paths are correct
4. Start nginx

SSL is difficult, and we use nginx in the live environments so copied configuration from there and cobbled the rest together. We can generate self-signed certificate with `mix phx.gen.cert` and use it in our nginx config.

Development nginx config:

```
# run in foreground instead of via daemon
worker_processes 1;
daemon off;

events {}
http {
  upstream phoenix_upstream {
    server 127.0.0.1:4000;
  }

  server {
    listen  4002 ssl;
    server_name identity_pki;

    ssl_certificate      /Users/USERNAME/projects/identity_pki/priv/cert/selfsigned.pem;
    ssl_certificate_key  /Users/USERNAME/projects/identity_pki/priv/cert/selfsigned_key.pem;
    ssl_verify_client optional_no_ca; # on;
    ssl_verify_depth 10;

    location / {
      proxy_redirect off;
      proxy_pass http://phoenix_upstream;
      proxy_set_header X-Client-Verify $ssl_client_verify;
      proxy_set_header X-Client-S-Dn $ssl_client_s_dn;
      proxy_set_header X-Client-I-Dn $ssl_client_i_dn;
      proxy_set_header X-Client-Serial $ssl_client_serial;
      proxy_set_header X-Client-Fingerprint $ssl_client_fingerprint;
      proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
    }
  }
}
```

```sh
# full path is needed
nginx -t -c /Users/USERNAME/projects/identity_pki/priv/nginx/ngninx_server.conf
# syntax is ok
# ngninx_server.conf test is successful
```

Start nginx:

```sh
# full path is needed
nginx -t -c /Users/USERNAME/projects/identity_pki/priv/nginx/ngninx_server.conf
```

