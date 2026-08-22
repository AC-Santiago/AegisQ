---
title: Inicio Rápido
description: Empezá a usar AegisQ en minutos — cifrá y descifrá datos con seguridad post-cuántica.
---

## Cifrar y Descifrar (API Recomendada)

La clase `AegisCipher` maneja todo el flujo KEM-DEM híbrido — encapsulación de clave con ML-KEM seguida de cifrado con AES-256-GCM — en una única llamada a `.encrypt()`.

```python
from aegisq import AegisCipher, SecurityLevel

# 1. El receptor genera un keypair
cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher_bob.generate_keypair()
# keypair.public_key  → 1184 bytes (compartilo abiertamente)
# keypair.secret_key  → 2400 bytes (mantenerlo privado)

# 2. El emisor cifra con la clave pública del receptor
cipher_alice = AegisCipher(level=SecurityLevel.ML_KEM_768)
encrypted_package = cipher_alice.encrypt(
    plaintext=b"Registros médicos ultra secretos",
    recipient_public_key=keypair.public_key,
)
# encrypted_package es un único objeto bytes:
# [ ML-KEM Capsule (1088 B) | Nonce (12 B) | Auth Tag (16 B) | Ciphertext ]

# 3. El receptor descifra
decrypted = cipher_bob.decrypt(
    encrypted_package=encrypted_package,
    secret_key=keypair.secret_key,
)
assert decrypted == b"Registros médicos ultra secretos"
```

## Operaciones KEM Crudas (Avanzado)

La clase `MlKem` expone operaciones ML-KEM de bajo nivel para usuarios que construyen protocolos custom:

```python
from aegisq import MlKem, SecurityLevel

kem = MlKem(level=SecurityLevel.ML_KEM_768)
keypair = kem.generate_keypair()

# Encapsular: produce una capsule + shared secret de 32 bytes
capsule, shared_secret = kem.encapsulate(keypair.public_key)

# Desencapsular: recupera el mismo shared secret de 32 bytes
recovered = kem.decapsulate(capsule, keypair.secret_key)
assert shared_secret == recovered
```

## ¿Qué Pasa Internamente?

Cuando llamás `cipher.encrypt()`, AegisQ realiza los siguientes pasos automáticamente:

1. **Encapsulación ML-KEM** — Genera un shared secret de 32 bytes resistente a quantum usando la clave pública del receptor
2. **Cifrado AES-256-GCM** — Usa ese shared secret como clave simétrica para cifrar tu plaintext con cifrado autenticado
3. **Ensamblado del Transit Package** — Empaqueta todo en un único objeto `bytes`: `[Capsule | Nonce | Auth Tag | Ciphertext]`

El descifrado invierte este proceso: la capsule se desencapsula para recuperar el shared secret, que luego se usa para descifrar y verificar el ciphertext.
