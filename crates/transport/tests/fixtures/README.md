# Test PKI

Certificates for [`tests/private_ca.rs`](../private_ca.rs). `ca.pem` signs `server.pem`
(`localhost` and `127.0.0.1`, private key `server.key`); `other-ca.pem` is an unrelated CA.
They are valid for 100 years. The CA's private key was discarded after signing, and none of
these keys protects anything. Regenerate them with `openssl` if a test needs a different
shape.
