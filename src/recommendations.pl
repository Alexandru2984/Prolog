:- module(recommendations, [
    recommendation/3,
    checklist_item/2
]).

recommendation(ssh_bruteforce, disable_ssh_password_login, 'Disable SSH password login and require key-based authentication.').
recommendation(ssh_root_public_login, disable_root_ssh_login, 'Disable direct root SSH login and use a named sudo-capable user.').
recommendation(ssh_password_login_enabled, disable_ssh_password_login, 'Disable SSH password login.').
recommendation(ssh_public_reachable, restrict_ssh_sources, 'Restrict SSH by firewall allowlist or VPN when practical.').
recommendation(app_public_bind, bind_app_to_127_0_0_1, 'Bind the application to 127.0.0.1 and expose it only through Nginx.').
recommendation(missing_reverse_proxy, add_nginx_reverse_proxy, 'Place the application behind Nginx with explicit proxy headers and timeouts.').
recommendation(missing_security_headers, add_security_headers, 'Add baseline security headers such as X-Content-Type-Options and Referrer-Policy.').
recommendation(missing_csp, enable_csp, 'Define a Content Security Policy suitable for the application.').
recommendation(missing_https, enable_https, 'Enable HTTPS and redirect HTTP to HTTPS.').
recommendation(missing_hsts, enable_hsts, 'Enable HSTS after confirming HTTPS works for all subpaths.').
recommendation(tls_no_auto_renewal, enable_cert_renewal, 'Enable automatic certificate renewal and monitor renewal failures.').
recommendation(legacy_tls_protocols, disable_legacy_tls, 'Disable legacy TLS protocols and weak ciphers.').
recommendation(origin_exposed_without_proxy, enable_cloudflare_proxy, 'Enable Cloudflare proxying or restrict origin access to trusted networks.').
recommendation(cloudflare_proxy_disabled, review_cloudflare_proxy, 'Enable Cloudflare proxying if the origin should not be directly reachable.').
recommendation(origin_ip_exposed, lock_origin_firewall, 'Restrict origin firewall rules to Cloudflare ranges or trusted ingress.').
recommendation(debug_public_app, disable_debug_mode, 'Disable debug mode before exposing the application publicly.').
recommendation(app_public_interface, bind_app_to_loopback, 'Bind the app to loopback and proxy through Nginx.').
recommendation(default_admin_path, protect_admin_path, 'Move, restrict, or strongly protect the default admin path.').
recommendation(missing_rate_limiting, add_rate_limiting, 'Add rate limiting at Nginx, the application layer, or both.').
recommendation(env_file_exposed, block_env_files, 'Block access to .env files and rotate any exposed secrets.').
recommendation(git_directory_exposed, block_git_directory, 'Block access to .git directories and remove deployment-time VCS metadata from web roots.').
recommendation(phpmyadmin_exposed, restrict_phpmyadmin, 'Remove phpMyAdmin from public exposure or protect it with strong network and auth controls.').
recommendation(database_public_weak_firewall, close_database_public_access, 'Bind PostgreSQL to localhost/private networks and enforce firewall restrictions.').
recommendation(postgres_public_exposure, close_database_public_access, 'Do not expose PostgreSQL directly to the public internet.').
recommendation(database_tls_not_required, require_database_tls, 'Require TLS for database connections that cross host or network boundaries.').
recommendation(unsafe_upload_extensions, validate_upload_extensions, 'Validate upload extensions and content type using an allowlist.').
recommendation(missing_upload_size_limit, set_upload_size_limit, 'Set strict upload size limits at Nginx and application layers.').
recommendation(no_backups_production, configure_backups, 'Configure automated backups and store them away from the host.').
recommendation(backups_not_tested, test_restore_process, 'Run and document restore tests on a regular schedule.').
recommendation(no_monitoring_production, add_monitoring, 'Add uptime, resource, certificate, and application health monitoring.').
recommendation(missing_log_rotation, enable_log_rotation, 'Enable log rotation and retention limits.').

checklist_item(verify_firewall, 'Confirm only intended public ports are open.').
checklist_item(loopback_binding, 'Confirm app processes bind to 127.0.0.1 unless they must be public.').
checklist_item(secret_rotation, 'Rotate secrets after any suspected exposure.').
checklist_item(cert_renewal, 'Monitor TLS certificate renewal.').
checklist_item(restore_drill, 'Schedule recurring backup restore drills.').
checklist_item(logging, 'Verify logs rotate and do not expose secrets.').
