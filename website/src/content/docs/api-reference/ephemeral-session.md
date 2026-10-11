---
title: EphemeralSession
description: Auto-generated session keypairs, closure behavior, and cleanup limitations.
---

## Overview

`EphemeralSession` generates a keypair internally, exposes its public key, and uses the private key for decryption. Closing the session marks it closed and drops its keypair reference.

:::caution[No secure-erasure or forward-secrecy guarantee]
`close()` does not guarantee that every Rust/Python copy of the secret is erased. Forward secrecy requires an appropriate authenticated protocol and secure disposal of past keys; the session helper alone does not provide it. See [Security Model](/internals/security-model/).
:::

```python
from aegisq import EphemeralSession

with EphemeralSession() as session:
    package = session.encrypt(b"Secret data", session.public_key)
    plaintext = session.decrypt(package)
# Session closed and keypair reference dropped on exit
```

## API Reference

### Constructor

```python
def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
```

### Properties

### `public_key` {#public_key}

Read-only public key. There is no public secret-key getter; this is API encapsulation, not protection from code or memory inspection within the process. Access after close raises `SessionExpiredError`.

```python
session = EphemeralSession()
print(session.public_key)  # bytes — share with sender
```

### Methods

### `encrypt(plaintext, recipient_public_key)` {#encrypt}

```python
def encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
```

Encrypts data using the hybrid ML-KEM + AES-256-GCM scheme.

### `decrypt(encrypted_package)` {#decrypt}

```python
def decrypt(self, encrypted_package: bytes) -> bytes
```

Decrypts a transit package using the ephemeral secret key.

### `close()` {#close}

```python
def close(self) -> None
```

Marks the session closed and drops its keypair reference. Safe to call multiple times. Subsequent `public_key`, `encrypt()`, and `decrypt()` calls raise `SessionExpiredError`; `level` remains readable.

## Context Manager

`EphemeralSession` supports the context manager protocol:

```python
with EphemeralSession() as session:
    package = session.encrypt(b"Secret data", session.public_key)
    plaintext = session.decrypt(package)
# Session automatically closed on exit; no complete erasure guarantee
```
