:- module(explanations, [explanation/2]).

explanation(ssh_bruteforce, 'SSH password login is enabled and SSH is reachable publicly.').
explanation(ssh_root_public_login, 'Root SSH login is enabled on a publicly reachable SSH service.').
explanation(ssh_password_login_enabled, 'SSH password login is enabled even though public reachability was not selected.').
explanation(ssh_public_reachable, 'SSH is publicly reachable; key-only login lowers the risk but the service still needs monitoring.').
explanation(app_public_bind, 'The application is bound to a public interface and no reverse proxy is enabled.').
explanation(missing_reverse_proxy, 'A public application is not protected by the expected Nginx reverse proxy boundary.').
explanation(missing_security_headers, 'The public service does not report baseline security headers.').
explanation(missing_csp, 'The public web application does not report a Content Security Policy.').
explanation(missing_https, 'A public application is reachable without HTTPS enabled.').
explanation(missing_hsts, 'HTTPS is enabled but HSTS is missing, allowing downgrade exposure.').
explanation(tls_no_auto_renewal, 'HTTPS is enabled but automatic certificate renewal is not configured.').
explanation(legacy_tls_protocols, 'TLS is enabled but legacy protocol versions are still allowed.').
explanation(origin_exposed_without_proxy, 'Cloudflare proxying is disabled and the origin IP is exposed.').
explanation(cloudflare_proxy_disabled, 'Cloudflare proxying is disabled for a public application.').
explanation(origin_ip_exposed, 'Cloudflare proxying is enabled but the origin IP is still exposed.').
explanation(debug_public_app, 'Debug mode is enabled on a public application.').
explanation(app_public_interface, 'The app is bound to a public interface even though Nginx is present.').
explanation(default_admin_path, 'A default admin path is enabled on a public application.').
explanation(missing_rate_limiting, 'A public application lacks rate limiting.').
explanation(env_file_exposed, 'An environment file is exposed publicly, which can leak secrets.').
explanation(git_directory_exposed, 'A .git directory is exposed publicly, which can leak source and history.').
explanation(phpmyadmin_exposed, 'phpMyAdmin is exposed on a public application surface.').
explanation(database_public_weak_firewall, 'PostgreSQL is publicly exposed and firewall posture is weak.').
explanation(postgres_public_exposure, 'PostgreSQL is reachable from the public internet.').
explanation(database_tls_not_required, 'The database connection does not require TLS for a public production service.').
explanation(unsafe_upload_extensions, 'Uploads are enabled without extension validation.').
explanation(missing_upload_size_limit, 'Uploads are enabled without a configured size limit.').
explanation(no_backups_production, 'The service is marked production but backups are not configured.').
explanation(backups_not_tested, 'Backups exist but restore testing is not confirmed.').
explanation(no_monitoring_production, 'The service is production but monitoring is not configured.').
explanation(missing_log_rotation, 'Log rotation is not configured.').
