:- module(facts, [
    known_fact/2,
    default_facts/1,
    sample_profile/3
]).

known_fact(ssh_password_login_enabled, 'SSH password login enabled').
known_fact(ssh_port_public, 'SSH reachable from the public internet').
known_fact(ssh_root_login_enabled, 'SSH root login enabled').
known_fact(nginx_reverse_proxy_enabled, 'Nginx reverse proxy enabled').
known_fact(nginx_has_hsts, 'Nginx sends HSTS').
known_fact(nginx_has_csp, 'Nginx/app sends CSP').
known_fact(nginx_has_security_headers, 'Nginx sends baseline security headers').
known_fact(https_enabled, 'HTTPS enabled').
known_fact(tls_auto_renewal_enabled, 'TLS auto-renewal enabled').
known_fact(tls_modern_protocols_only, 'TLS uses modern protocols only').
known_fact(cloudflare_proxy_enabled, 'Cloudflare proxy enabled').
known_fact(origin_ip_exposed, 'Origin IP exposed').
known_fact(app_bound_to_public_interface, 'App bound to public interface').
known_fact(public_app, 'Application is publicly reachable').
known_fact(debug_mode_enabled, 'Debug mode enabled').
known_fact(default_admin_path_enabled, 'Default admin path enabled').
known_fact(app_has_rate_limiting, 'Application has rate limiting').
known_fact(database_in_use, 'Application uses a database connection').
known_fact(postgres_publicly_exposed, 'PostgreSQL publicly exposed').
known_fact(database_requires_tls, 'Database requires TLS').
known_fact(weak_firewall_posture, 'Firewall posture is weak').
known_fact(exposes_phpmyadmin, 'phpMyAdmin exposed').
known_fact(exposes_env_file, '.env file exposed').
known_fact(exposes_git_directory, '.git directory exposed').
known_fact(uploads_enabled, 'Uploads enabled').
known_fact(upload_extension_validation, 'Upload extension validation enabled').
known_fact(upload_size_limit, 'Upload size limit configured').
known_fact(has_backups, 'Backups configured').
known_fact(backups_tested, 'Backups tested').
known_fact(has_monitoring, 'Monitoring configured').
known_fact(has_log_rotation, 'Log rotation configured').
known_fact(production_service, 'Production service').

default_facts([
    ssh_password_login_enabled(false),
    ssh_port_public(false),
    ssh_root_login_enabled(false),
    nginx_reverse_proxy_enabled(true),
    nginx_has_hsts(false),
    nginx_has_csp(false),
    nginx_has_security_headers(false),
    https_enabled(true),
    tls_auto_renewal_enabled(true),
    tls_modern_protocols_only(true),
    cloudflare_proxy_enabled(false),
    origin_ip_exposed(true),
    app_bound_to_public_interface(false),
    public_app(true),
    debug_mode_enabled(false),
    default_admin_path_enabled(false),
    app_has_rate_limiting(false),
    database_in_use(false),
    postgres_publicly_exposed(false),
    database_requires_tls(false),
    weak_firewall_posture(false),
    exposes_phpmyadmin(false),
    exposes_env_file(false),
    exposes_git_directory(false),
    uploads_enabled(false),
    upload_extension_validation(true),
    upload_size_limit(true),
    has_backups(false),
    backups_tested(false),
    has_monitoring(true),
    has_log_rotation(true),
    production_service(true)
]).

sample_profile(generic_hardened_vps, 'Generic hardened VPS', [
    ssh_password_login_enabled(false), ssh_port_public(true), ssh_root_login_enabled(false),
    nginx_reverse_proxy_enabled(true), nginx_has_hsts(true), nginx_has_csp(true),
    nginx_has_security_headers(true), https_enabled(true), tls_auto_renewal_enabled(true),
    tls_modern_protocols_only(true), cloudflare_proxy_enabled(true), origin_ip_exposed(false),
    app_bound_to_public_interface(false), public_app(true), debug_mode_enabled(false),
    default_admin_path_enabled(false), app_has_rate_limiting(true),
    database_in_use(false),
    postgres_publicly_exposed(false), database_requires_tls(true), weak_firewall_posture(false),
    exposes_phpmyadmin(false), exposes_env_file(false), exposes_git_directory(false),
    uploads_enabled(false), upload_extension_validation(true), upload_size_limit(true),
    has_backups(true), backups_tested(true), has_monitoring(true), has_log_rotation(true),
    production_service(true)
]).
sample_profile(weak_vps, 'Weak VPS', [
    ssh_password_login_enabled(true), ssh_port_public(true), ssh_root_login_enabled(true),
    nginx_reverse_proxy_enabled(false), nginx_has_hsts(false), nginx_has_csp(false),
    nginx_has_security_headers(false), https_enabled(false), tls_auto_renewal_enabled(false),
    tls_modern_protocols_only(false), cloudflare_proxy_enabled(false), origin_ip_exposed(true),
    app_bound_to_public_interface(true), public_app(true), debug_mode_enabled(true),
    default_admin_path_enabled(true), app_has_rate_limiting(false),
    database_in_use(true),
    postgres_publicly_exposed(true), database_requires_tls(false), weak_firewall_posture(true),
    exposes_phpmyadmin(true), exposes_env_file(true), exposes_git_directory(true),
    uploads_enabled(true), upload_extension_validation(false), upload_size_limit(false),
    has_backups(false), backups_tested(false), has_monitoring(false), has_log_rotation(false),
    production_service(true)
]).
sample_profile(django_nginx, 'Django app behind Nginx', [
    ssh_password_login_enabled(false), ssh_port_public(true), ssh_root_login_enabled(false),
    nginx_reverse_proxy_enabled(true), nginx_has_hsts(true), nginx_has_csp(false),
    nginx_has_security_headers(true), https_enabled(true), tls_auto_renewal_enabled(true),
    tls_modern_protocols_only(true), cloudflare_proxy_enabled(false), origin_ip_exposed(true),
    app_bound_to_public_interface(false), public_app(true), debug_mode_enabled(false),
    default_admin_path_enabled(true), app_has_rate_limiting(true),
    database_in_use(true),
    postgres_publicly_exposed(false), database_requires_tls(false), weak_firewall_posture(false),
    exposes_phpmyadmin(false), exposes_env_file(false), exposes_git_directory(false),
    uploads_enabled(true), upload_extension_validation(true), upload_size_limit(true),
    has_backups(true), backups_tested(false), has_monitoring(true), has_log_rotation(true),
    production_service(true)
]).
sample_profile(shiny_r_nginx, 'Shiny/R app behind Nginx', [
    ssh_password_login_enabled(false), ssh_port_public(true), ssh_root_login_enabled(false),
    nginx_reverse_proxy_enabled(true), nginx_has_hsts(true), nginx_has_csp(false),
    nginx_has_security_headers(true), https_enabled(true), tls_auto_renewal_enabled(true),
    tls_modern_protocols_only(true), cloudflare_proxy_enabled(false), origin_ip_exposed(true),
    app_bound_to_public_interface(false), public_app(true), debug_mode_enabled(false),
    default_admin_path_enabled(false), app_has_rate_limiting(false),
    database_in_use(false),
    postgres_publicly_exposed(false), database_requires_tls(false), weak_firewall_posture(false),
    exposes_phpmyadmin(false), exposes_env_file(false), exposes_git_directory(false),
    uploads_enabled(false), upload_extension_validation(true), upload_size_limit(true),
    has_backups(true), backups_tested(false), has_monitoring(true), has_log_rotation(true),
    production_service(true)
]).
sample_profile(static_cloudflare, 'Static site behind Cloudflare', [
    ssh_password_login_enabled(false), ssh_port_public(true), ssh_root_login_enabled(false),
    nginx_reverse_proxy_enabled(true), nginx_has_hsts(true), nginx_has_csp(true),
    nginx_has_security_headers(true), https_enabled(true), tls_auto_renewal_enabled(true),
    tls_modern_protocols_only(true), cloudflare_proxy_enabled(true), origin_ip_exposed(false),
    app_bound_to_public_interface(false), public_app(true), debug_mode_enabled(false),
    default_admin_path_enabled(false), app_has_rate_limiting(true),
    database_in_use(false),
    postgres_publicly_exposed(false), database_requires_tls(false), weak_firewall_posture(false),
    exposes_phpmyadmin(false), exposes_env_file(false), exposes_git_directory(false),
    uploads_enabled(false), upload_extension_validation(true), upload_size_limit(true),
    has_backups(true), backups_tested(true), has_monitoring(true), has_log_rotation(true),
    production_service(true)
]).
sample_profile(api_uploads, 'API service with uploads', [
    ssh_password_login_enabled(false), ssh_port_public(true), ssh_root_login_enabled(false),
    nginx_reverse_proxy_enabled(true), nginx_has_hsts(true), nginx_has_csp(false),
    nginx_has_security_headers(true), https_enabled(true), tls_auto_renewal_enabled(true),
    tls_modern_protocols_only(true), cloudflare_proxy_enabled(true), origin_ip_exposed(false),
    app_bound_to_public_interface(false), public_app(true), debug_mode_enabled(false),
    default_admin_path_enabled(false), app_has_rate_limiting(false),
    database_in_use(true),
    postgres_publicly_exposed(false), database_requires_tls(true), weak_firewall_posture(false),
    exposes_phpmyadmin(false), exposes_env_file(false), exposes_git_directory(false),
    uploads_enabled(true), upload_extension_validation(false), upload_size_limit(true),
    has_backups(true), backups_tested(false), has_monitoring(true), has_log_rotation(true),
    production_service(true)
]).
