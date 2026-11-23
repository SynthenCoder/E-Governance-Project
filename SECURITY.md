# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report them privately through GitHub: **Security tab → "Report a vulnerability"**,
or email the maintainer (see the README). Include steps to reproduce and the
impact you observed. You can expect a reply within a few days.

## Secrets

This project never stores credentials in the repository. All secrets
(`SECRET_KEY`, `EMAIL_PASS`, `ADMIN_SETUP_CODE`) are read from environment
variables. If you ever commit a secret by mistake, revoke it immediately —
deleting it from the code does not remove it from git history.
