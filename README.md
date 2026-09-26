# Componenta Auth Password

Password authentication for Componenta Auth 3.

The package owns password payload extraction, password verification, browser
password login, and password-reset HTTP contracts. Password persistence and
application password policy stay with the application/identity model.

Browser login requires a Componenta pre-authentication transaction and always
issues a fresh `AuthSession`. Remember-me is deliberately a separate
capability.
