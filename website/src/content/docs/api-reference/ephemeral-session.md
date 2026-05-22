---
title: EphemeralSession
description: Forward secrecy via auto-generated keypairs
---

## Overview

`EphemeralSession` provides forward secrecy by generating a keypair internally and destroying the secret key when the session closes.

```python
from aegisq import EphemeralSession

with EphemeralSession() as session:
    package = session.encrypt(b"Secret data", session.public_key)
    plaintext = session.decrypt(package)
# Secret key destroyed on exit
```

## API Reference

### Constructor

```python
def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
```

### Properties

### `public_key` {#public_key}

Read-only public key. The secret key is never exposed.

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

Closes the session and destroys the secret key. Safe to call multiple times.

## Context Manager

`EphemeralSession` supports the context manager protocol:

```python
with EphemeralSession() as session:
    package = session.encrypt(b"Secret data", session.public_key)
    plaintext = session.decrypt(package)
# Secret key automatically destroyed on exit
```