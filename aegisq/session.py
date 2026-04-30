"""Clase EphemeralSession — Sesiones efimeras con forward secrecy.

Proporciona un mecanismo de cifrado donde la clave privada efimera es
generada internamente y destruida automaticamente al cerrar la sesion.

Esto provee **forward secrecy**: si alguien roba la clave privada guardada,
no puede descifrar mensajes anteriores porque las claves efimeras fueron
destruidas.

Ejemplo::

    from aegisq import EphemeralSession

    with EphemeralSession() as session:
        # Solo necesitas la clave publica para cifrar
        package = session.encrypt(
            plaintext=b"Datos secretos",
            recipient_public_key=session.public_key,
        )
        # descifrar mensajes destinados a esta sesion
        plaintext = session.decrypt(package)

    # Al salir del context manager, la clave privada es destruida
"""

from __future__ import annotations

from typing import Self

from aegisq._aegisq_core import (
    KeyPair,
    SecurityLevel,
    decrypt_hybrid,
    encrypt_hybrid,
    generate_keypair,
)
from aegisq.exceptions import SessionExpiredError


class EphemeralSession:
    """Sesion efimera con clave privada autogestionada.

    Genera internamente un par de claves efimero y destruye la clave
    secreta automaticamente al cerrar la sesion (via ``close()`` o
    context manager).

    Args:
        level: Nivel de seguridad ML-KEM. Por defecto
            ``SecurityLevel.ML_KEM_768``.

    Attributes:
        public_key: Clave publica efimera (solo lectura).

    Raises:
        RngError: Si el CSPRNG del sistema operativo no esta disponible.

    Example::

        with EphemeralSession() as session:
            package = session.encrypt(
                plaintext=b"secret data",
                recipient_public_key=session.public_key,
            )
    """

    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None:
        self._level = level
        self._keypair: KeyPair | None = generate_keypair(level)
        self._closed: bool = False

    @property
    def public_key(self) -> bytes:
        """Clave publica efimera (solo lectura).

        Esta clave es la unica que se comparte con el emisor.
        La clave secreta asociada NUNCA se expone.
        """
        self._check_closed()
        return bytes(self._keypair.public_key)

    @property
    def level(self) -> SecurityLevel:
        """Nivel de seguridad configurado."""
        return self._level

    def encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> bytes:
        """Cifra datos usando el esquema hibrido de esta sesion.

        Args:
            plaintext: Datos a cifrar (cualquier longitud).
            recipient_public_key: Clave publica del receptor.

                En el flujo canonico, es ``session.public_key`` del receptor.

        Returns:
            Transit Package como ``bytes``.

        Raises:
            SessionExpiredError: Si la sesion ya fue cerrada.
            InvalidParameterError: Si la clave publica tiene tamano incorrecto.
            RngError: Si el CSPRNG del OS no esta disponible.
        """
        self._check_closed()
        return bytes(encrypt_hybrid(recipient_public_key, plaintext, self._level))

    def decrypt(self, encrypted_package: bytes) -> bytes:
        """Descifra un Transit Package usando la clave secreta efimera.

        Args:
            encrypted_package: Transit Package recibido.

        Returns:
            Plaintext original como ``bytes``.

        Raises:
            SessionExpiredError: Si la sesion ya fue cerrada.
            DecryptionError: Si el Auth Tag de AES-GCM es invalido
                (payload manipulado o clave incorrecta).
            InvalidParameterError: Si el paquete tiene tamano incorrecto.
        """
        self._check_closed()
        if self._keypair is None:
            raise SessionExpiredError("Sesion efimera sin clave privada")
        return bytes(
            decrypt_hybrid(encrypted_package, self._keypair.secret_key, self._level)
        )

    def close(self) -> None:
        """Cierra la sesion y destruye la clave secreta efimera.

        Este metodo es seguro llamarlo multiples veces.

        Nota: la zeroizacion de la clave secreta en memoria es responsabilidad
        de la capa Rust. Ver Issue #10 para tracking de esta mejora.
        """
        if self._closed:
            return
        self._closed = True
        self._keypair = None

    def _check_closed(self) -> None:
        """Lanza SessionExpiredError si la sesion esta cerrada."""
        if self._closed:
            raise SessionExpiredError(
                "Sesion efimera cerrada. No se puede usar after close()."
            )

    def __enter__(self) -> Self:
        """Entry del context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit del context manager - destruye la clave secreta."""
        self.close()

    def __del__(self) -> None:
        """Destructor - asegura destruccion de clave en lo posible.

        Protegido contra objetos parcialmente inicializados si __init__ fallo.
        """
        try:
            if not getattr(self, "_closed", True):
                self.close()
        except Exception:
            # Un destructor nunca debe propagar excepciones, especialmente
            # si el objeto quedo parcialmente inicializado.
            pass

    def __repr__(self) -> str:
        status = "closed" if self._closed else "open"
        return f"EphemeralSession(level={self._level!r}, {status})"
