# Prolog Security Expert System

Production web application for defensive VPS, website, and self-hosted application posture analysis. Users describe server and application facts, and SWI-Prolog rules infer risks, severities, explanations, recommendations, checklist items, and a deterministic score.

Deployment domain: `https://prolog.micutu.com`

## Features

- Dark responsive web UI with dashboard, audit form, result cards, saved report links, JSON export, and Markdown export.
- Rule modules for SSH, Nginx, TLS, Cloudflare, app runtime, database exposure, uploads, backups, monitoring, and logging.
- Sample profiles: generic hardened VPS, weak VPS, Django behind Nginx, Shiny/R behind Nginx, static site behind Cloudflare, and API service with uploads.
- Public demo mode for guests and session-based admin login for live probes, exports, and API access.
- JSON-file persistence in `data/exports/`.
- plunit test suite.

## Stack

- SWI-Prolog HTTP server libraries
- SWI-Prolog `html_write`, `http_dispatch`, `http_json`, and plunit
- HTML/CSS/vanilla JavaScript
- Nginx reverse proxy
- Certbot SSL
- systemd service

## Folder Structure

- `server.pl`, `app.pl`: application entrypoints
- `src/`: config, routes, UI rendering, rule engine, scoring, persistence, exports
- `public/`: CSS and JavaScript
- `tests/`: plunit tests
- `scripts/`: helper scripts and optional SQL migration
- `logs/`: service logs directory
- `data/samples/`: sample profile descriptors
- `data/exports/`: generated JSON and Markdown audit reports
- `views/`: reserved for future template files

## Environment Variables

Configuration is loaded from `.env`. Never commit `.env` with real secrets.

Key variables:

- `APP_HOST=127.0.0.1`
- `APP_PORT=3050`
- `APP_ENV=production`
- `APP_NAME=Prolog Security Expert System`
- `DB_BACKEND=json_file`
- `LOG_DIR=/home/micu/prolog/logs`
- `DATA_DIR=/home/micu/prolog/data`
- `APP_USERNAME=admin`
- `APP_PASSWORD=<set in .env>`

PostgreSQL placeholders are present in `.env`, but v1 uses JSON-file persistence to avoid provisioning production database credentials or ODBC DSNs automatically.

## Rule Engine

Facts are represented as Prolog terms:

```prolog
ssh_password_login_enabled(true).
ssh_port_public(true).
cloudflare_proxy_enabled(false).
nginx_has_hsts(false).
app_bound_to_public_interface(true).
postgres_publicly_exposed(false).
has_backups(false).
has_monitoring(true).
```

Rules infer values such as:

```prolog
risk(high, ssh_bruteforce).
risk(critical, app_public_bind).
risk(medium, missing_hsts).
recommendation(disable_ssh_password_login).
explanation(ssh_bruteforce, "SSH password login is enabled and SSH is reachable publicly.").
```

Combined-risk examples:

- SSH password login enabled plus public SSH gives `high` risk.
- App bound to public interface with no reverse proxy gives `critical` risk.
- Debug mode on a public app gives `critical` risk.
- Uploads without extension validation gives `high` risk.
- Public database plus weak firewall gives `critical` risk.

## Scoring

The score starts at 100 and subtracts:

- `critical`: 25
- `high`: 15
- `medium`: 8
- `low`: 3
- `info`: 0

The score is clamped between 0 and 100.

Posture:

- 90-100: `strong`
- 75-89: `good`
- 50-74: `needs_attention`
- 25-49: `weak`
- 0-24: `critical`

## Run Manually

```bash
cd /home/micu/prolog
swipl -q -f server.pl -- --port 3050
```

The app binds to `127.0.0.1` only. Public traffic must go through Nginx.

## Tests

```bash
cd /home/micu/prolog
swipl -q -s tests/run_tests.pl -t run_tests
```

or:

```bash
./scripts/run_tests.sh
```

## Database Notes

The production app currently uses JSON-file persistence. Exports are stored under `data/exports/`, ignored by Git, and protected behind admin session login because reports can contain sensitive posture information.

## Authentication

Guests can browse the dashboard and run demo audits that use mock data only. Guests cannot run live target probes, save reports, access exports, or call the JSON API.

Admin login is available at `/login` and uses `APP_USERNAME` / `APP_PASSWORD` from `.env`. The session cookie is named `prolog_security_session`, expires after one hour of inactivity, and is flagged by Nginx as `Secure`, `HttpOnly`, and `SameSite=Strict`.

An idempotent PostgreSQL schema is provided in `scripts/migrate_db.sql` for future DB-backed sessions. Do not hardcode credentials; use `.env` and provision a dedicated database user manually.

## systemd

Service name:

```text
prolog-security.service
```

Expected properties:

- `User=micu`
- `WorkingDirectory=/home/micu/prolog`
- `EnvironmentFile=/home/micu/prolog/.env`
- Starts SWI-Prolog with `server.pl`
- Restarts automatically
- Binds only to `127.0.0.1`

## Nginx

Dedicated config path:

```text
/etc/nginx/sites-available/prolog.micutu.com
```

It proxies `prolog.micutu.com` to `http://127.0.0.1:3050` and includes:

- `Host`
- `X-Real-IP`
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- timeouts
- `client_max_body_size 2M`

Always run `sudo nginx -t` before reloading Nginx.

## SSL

Certbot is used with the Nginx plugin for:

```text
prolog.micutu.com
```

Certificate renewals should be tested with:

```bash
sudo certbot renew --dry-run
```

## Troubleshooting

App not starting:
Check `journalctl -u prolog-security.service -n 100 --no-pager` and verify SWI-Prolog can load `server.pl`.

Port occupied:
Run `./scripts/choose_port.sh 3050`, update `.env`, systemd, and Nginx, then restart only this service and reload Nginx after `nginx -t`.

Nginx 502:
Confirm `prolog-security.service` is active and listening on `127.0.0.1:3050`.

Database connection failure:
v1 does not require PostgreSQL at runtime. If you enable DB persistence later, verify credentials, database existence, ODBC packages, and network binding.

Prolog module loading issues:
Run the test command from `/home/micu/prolog` so relative module paths resolve correctly.

Certbot issues:
Verify DNS points to this VPS, Nginx config passes, and no existing server block conflicts with `prolog.micutu.com`.

## Safety Notes

- This is a defensive security tool only.
- The app must not be exposed directly to the public internet.
- Do not commit `.env`.
- Generated reports can contain sensitive posture data and are ignored by Git.
- The owner handles Git commit and push manually.
