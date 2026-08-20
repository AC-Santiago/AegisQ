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

Como **context manager** (zeroizacion proactiva al salir)::

    with AegisCipher(level=SecurityLevel.ML_KEM_768) as cipher:
        kp = cipher.generate_keypair()
        pkg = cipher.encrypt(b"hola", kp.public_key)
        # __exit__ zeroiza proactivamente cualquier buffer Python-side
        # registrado durante la sesion.

Nota sobre zeroizacion:
    Hoy ``encrypt()`` y ``decrypt()`` son one-shot: el shared secret se
    deriva y zeroiza dentro de Rust (via wrappers ``Zeroizing``) en cada
    llamada, sin retencion Python-side. El context manager se
    proporciona como contrato forward-compatible: si una API futura
    mantiene material criptografico Python-side, ese material se
    registra con ``_register_session_buffer`` y se zeroiza
    deterministicamente al salir del ``with``, sin depender del GC.
"""

from __future__ import annotations

import asyncio
from typing import Self

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

    Soporta uso como **context manager**. Al salir del bloque ``with``, se
    zeroizan proactivamente todos los buffers Python-side registrados
    durante la sesion. Hoy la API publica no retiene material; el
    protocolo existe para forward-compatibility con futuras APIs de
    sesion / streaming.
    """

    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None:
        self._level = level
        self._entered: bool = False
        # Buffers Python-side retenidos durante la sesion. Cada uno es
        # un bytearray para que podamos sobrescribir su contenido in-place.
        self._session_buffers: list[bytearray] = []

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
        state = "active" if self._entered else "inactive"
        return f"AegisCipher(level={self._level!r}, {state})"

    # ── Context manager: zeroizacion proactiva al salir ──────────────────────

    def __enter__(self) -> Self:
        """Marca la sesion como activa y devuelve ``self``.

        Usar dentro de un bloque ``with``::

            with AegisCipher() as cipher:
                cipher.encrypt(b"...", pk)
                # __exit__ zeroiza proactivamente cualquier buffer
                # Python-side registrado durante la sesion.
        """
        self._entered = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Sale del contexto zeroizando proactivamente los buffers retenidos.

        No suprime excepciones: cualquier error dentro del bloque ``with``
        se propaga al llamador despues de la zeroizacion.
        """
        self._zeroize_session()
        return False  # do not suppress exceptions

    def _register_session_buffer(self, buf: bytearray) -> bytearray:
        """Registra un ``bytearray`` para zeroizacion proactiva al ``__exit__``.

        API interna usada por futuras features (ej. ``bind_session``,
        ``encrypt_stream``) que retengan material criptografico Python-side.
        El material se sobrescribe con ceros deterministicamente al salir
        del contexto, sin depender de la recoleccion de basura.

        Args:
            buf: buffer mutable a registrar (se modifica in-place).

        Returns:
            El mismo buffer (para encadenar).
        """
        self._session_buffers.append(buf)
        return buf

    def _zeroize_session(self) -> None:
        """Sobrescribe con ceros todos los buffers registrados y limpia la lista.

        Llamado por ``__exit__``. Idempotente: invocarlo multiples veces
        es seguro. No lanza excepciones si no hay buffers registrados.
        """
        for buf in self._session_buffers:
            # Sobrescribimos in-place para que cualquier referencia
            # externa al bytearray vea ceros, no solo esta lista.
            for i in range(len(buf)):
                buf[i] = 0
        self._session_buffers.clear()
        self._entered = False

    async def encrypt_async(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
    ) -> bytes:
        """Cifra datos de forma asincrona usando el esquema hibrido.

        Este metodo ejecuta la operacion de cifrado en un ThreadPoolExecutor
        sin bloquear el event loop. No requiere cambios en Rust ni PyO3.

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
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.encrypt,
            plaintext,
            recipient_public_key,
        )

    async def decrypt_async(
        self,
        encrypted_package: bytes,
        secret_key: bytes,
    ) -> bytes:
        """Descifra un Transit Package de forma asincrona.

        Este metodo ejecuta la operacion de descifrado en un ThreadPoolExecutor
        sin bloquear el event loop. No requiere cambios en Rust ni PyO3.

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
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.decrypt,
            encrypted_package,
            secret_key,
        )
