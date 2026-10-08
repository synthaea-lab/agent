Test-only PKI for `tests/private_ca.rs` (#658): `ca.pem` signs `server.pem`
(`localhost` / `127.0.0.1`, key `server.key`); `other-ca.pem` is an unrelated CA.
Valid for 100 years. The CA's private key was discarded after signing, and none of
these keys protects anything. Regenerate with `openssl` if a test ever needs a
different shape.
