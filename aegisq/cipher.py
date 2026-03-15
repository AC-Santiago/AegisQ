"""Clase AegisCipher — API de alto nivel para cifrado hibrido post-cuantico.

Esta es la clase principal que los usuarios finales deben usar.
Abstrae todo el flujo KEM-DEM (ML-KEM + AES-256-GCM) en una interfaz
simple de ``encrypt()`` / ``decrypt()``.

Ejemplo::

    from aegisq import AegisCipher, SecurityLevel

    # Receptor genera su keypair
    cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
    keypair = cipher_bob.generate_keypair()

    # Emisor cifra con la clave publica del receptor
    cipher_alice = AegisCipher(level=SecurityLevel.ML_KEM_768)
    package = cipher_alice.encrypt(
        plaintext=b"Datos secretos",
        recipient_public_key=keypair.public_key,
    )

    # Receptor descifra
    plaintext = cipher_bob.decrypt(
        encrypted_package=package,
        secret_key=keypair.secret_key,
    )
"""

from __future__ import annotations

from aegisq._aegisq_core import (
    KeyPair,
    SecurityLevel,
    decrypt_hybrid,
    encrypt_hybrid,
    generate_keypair,
)


class AegisCipher:
    """Motor de cifrado hibrido post-cuantico (ML-KEM + AES-256-GCM).

    Args:
        level: Nivel de seguridad ML-KEM. Por defecto ``SecurityLevel.ML_KEM_768``.
    """

    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None:
        self._level = level

    @property
    def level(self) -> SecurityLevel:
        """Nivel de seguridad configurado."""
        return self._level

    def generate_keypair(self) -> KeyPair:
        """Genera un par de claves ML-KEM para este nivel de seguridad.

        Returns:
            KeyPair con ``public_key`` y ``secret_key`` como ``bytes``.

        Raises:
            RngError: Si el CSPRNG del sistema operativo no esta disponible.
        """
        return generate_keypair(self._level)

    def encrypt(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
    ) -> bytes:
        """Cifra datos usando el esquema hibrido ML-KEM + AES-256-GCM.

        Flujo interno:
            1. ML-KEM.Encaps genera capsule + shared_secret
            2. AES-256-GCM cifra plaintext con shared_secret como clave
            3. Ensambla el Transit Package

        Args:
            plaintext: Datos a cifrar (cualquier longitud).
            recipient_public_key: Clave publica ML-KEM del receptor.

        Returns:
            Transit Package como ``bytes``:
            ``[ML-KEM Capsule | AES Nonce (12B) | Auth Tag (16B) | Ciphertext]``

        Raises:
            InvalidParameterError: Si la clave publica tiene tamano incorrecto.
            RngError: Si el CSPRNG del OS no esta disponible.
        """
        return bytes(encrypt_hybrid(recipient_public_key, plaintext, self._level))

    def decrypt(
        self,
        encrypted_package: bytes,
        secret_key: bytes,
    ) -> bytes:
        """Descifra un Transit Package usando la clave secreta.

        Args:
            encrypted_package: Transit Package completo recibido.
            secret_key: Clave secreta ML-KEM propia.

        Returns:
            Plaintext original como ``bytes``.

        Raises:
            DecryptionError: Si el Auth Tag de AES-GCM es invalido
                (payload manipulado o clave incorrecta).
            InvalidParameterError: Si el paquete tiene tamano incorrecto.
        """
        return bytes(decrypt_hybrid(encrypted_package, secret_key, self._level))

    def __repr__(self) -> str:
        return f"AegisCipher(level={self._level!r})"
