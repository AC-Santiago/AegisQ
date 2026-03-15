"""Clase MlKem — Operaciones KEM crudas para usuarios avanzados.

Esta clase expone las operaciones ML-KEM (Key Encapsulation Mechanism)
de bajo nivel: generacion de claves, encapsulacion y desencapsulacion.

Para la mayoria de los casos de uso, se recomienda usar ``AegisCipher``
en su lugar, que integra automaticamente AES-256-GCM.

Ejemplo::

    from aegisq import MlKem, SecurityLevel

    kem = MlKem(level=SecurityLevel.ML_KEM_768)
    keypair = kem.generate_keypair()

    capsule, shared_secret = kem.encapsulate(keypair.public_key)
    recovered_secret = kem.decapsulate(capsule, keypair.secret_key)

    assert shared_secret == recovered_secret
"""

from __future__ import annotations

from aegisq._aegisq_core import (
    KeyPair,
    SecurityLevel,
)
from aegisq._aegisq_core import (
    decapsulate as _decapsulate,
)
from aegisq._aegisq_core import (
    encapsulate as _encapsulate,
)
from aegisq._aegisq_core import (
    generate_keypair as _generate_keypair,
)


class MlKem:
    """Interfaz ML-KEM de bajo nivel (FIPS 203).

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
        """Genera un par de claves ML-KEM.

        Returns:
            KeyPair con ``public_key`` y ``secret_key`` como ``bytes``.

        Raises:
            RngError: Si el CSPRNG del OS no esta disponible.
        """
        return _generate_keypair(self._level)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsula un shared secret con la clave publica del receptor.

        Corresponde a FIPS 203 Alg. 16 (ML-KEM.Encaps).

        Args:
            public_key: Clave publica ML-KEM del receptor.

        Returns:
            Tupla ``(capsule, shared_secret)`` donde ambos son ``bytes``.
            El ``shared_secret`` tiene 32 bytes para todos los niveles.

        Raises:
            InvalidParameterError: Si la clave publica tiene tamano incorrecto.
        """
        capsule, shared_secret = _encapsulate(public_key, self._level)
        return bytes(capsule), bytes(shared_secret)

    def decapsulate(self, capsule: bytes, secret_key: bytes) -> bytes:
        """Desencapsula el shared secret con la clave secreta propia.

        Corresponde a FIPS 203 Alg. 17 (ML-KEM.Decaps).

        NOTA: Si el ciphertext es invalido, esta funcion NO lanza error.
        Devuelve silenciosamente un shared secret derivado de material
        interno (implicit rejection, FIPS 203 §7.3). Esto previene
        ataques CCA2.

        Args:
            capsule: Capsula ML-KEM recibida.
            secret_key: Clave secreta ML-KEM propia.

        Returns:
            Shared secret de 32 bytes como ``bytes``.

        Raises:
            DecapsulationError: Solo para errores estructurales (tamano incorrecto).
        """
        return bytes(_decapsulate(capsule, secret_key, self._level))

    def __repr__(self) -> str:
        return f"MlKem(level={self._level!r})"
