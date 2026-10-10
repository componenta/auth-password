# Componenta Auth Password

Password authentication for Componenta Auth 3.

The package owns password payload extraction, password verification, browser
password login, and password-reset HTTP contracts. Password persistence and
application password policy stay with the application/identity model.

Browser login requires a Componenta pre-authentication transaction and always
issues a fresh `AuthSession`. Remember-me is deliberately a separate
capability.

## Version 2 compatibility

Version 2.0.0 requires `componenta/auth-session-http ^2.0.1`. Its browser
security contract uses `componenta/http-csrf-middleware ^3.0`, which validates
Origin/Referer on unsafe requests and rejects missing origin metadata by
default. Upgrade the session HTTP and CSRF packages together; do not disable
origin validation to preserve older clients.

See [the changelog](CHANGELOG.md) for migration details. Session issuance
continues to use the shared Componenta Auth session APIs; this package does
not create an independent session or CSRF stack.
