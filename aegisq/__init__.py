"""AegisQ — Motor de criptografia post-cuantica.

Implementa una arquitectura hibrida KEM-DEM que combina:
- ML-KEM (FIPS 203) para encapsulacion de claves resistente a computadoras cuanticas
- AES-256-GCM para cifrado autenticado del payload

Uso basico::

    from aegisq import AegisCipher, SecurityLevel

    cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
    keypair = cipher.generate_keypair()

    package = cipher.encrypt(
        plaintext=b"Datos secretos",
        recipient_public_key=keypair.public_key,
    )

    plaintext = cipher.decrypt(
        encrypted_package=package,
        secret_key=keypair.secret_key,
    )
"""

from aegisq._aegisq_core import KeyPair, SecurityLevel
from aegisq.exceptions import (
    AegisQError,
    DecapsulationError,
    DecryptionError,
    InvalidParameterError,
    RngError,
)
from aegisq.cipher import AegisCipher
from aegisq.kem import MlKem

__all__ = [
    "AegisCipher",
    "KeyPair",
    "MlKem",
    "SecurityLevel",
    "AegisQError",
    "DecapsulationError",
    "DecryptionError",
    "InvalidParameterError",
    "RngError",
]

__version__ = "0.1.0"
