"""Type stubs para el modulo nativo ``aegisq._aegisq_core``.

Proporciona autocompletado y type checking para IDEs (PyCharm, VS Code)
y herramientas de analisis estatico (mypy, pyright).
"""

from typing import overload

# --- Excepciones ---

class AegisQError(Exception):
    """Base exception for all AegisQ errors."""

    ...

class DecapsulationError(AegisQError):
    """ML-KEM structural decapsulation error."""

    ...

class DecryptionError(AegisQError):
    """AES-GCM authentication tag verification failed."""

    ...

class InvalidParameterError(AegisQError, ValueError):
    """Invalid parameter (buffer size, security level)."""

    ...

class RngError(AegisQError):
    """CSPRNG not available from the operating system."""

    ...

# --- Enums ---

class SecurityLevel:
    """Nivel de seguridad ML-KEM."""

    ML_KEM_512: SecurityLevel
    ML_KEM_768: SecurityLevel
    ML_KEM_1024: SecurityLevel

# --- Clases ---

class KeyPair:
    """Par de claves ML-KEM."""

    @property
    def public_key(self) -> bytes:
        """Clave publica como bytes."""
        ...

    @property
    def secret_key(self) -> bytes:
        """Clave secreta como bytes."""
        ...

    @property
    def level(self) -> SecurityLevel:
        """Nivel de seguridad con el que se genero."""
        ...

# --- Funciones KEM ---

def generate_keypair(
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> KeyPair:
    """Genera un par de claves ML-KEM."""
    ...

def encapsulate(
    public_key: bytes,
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> tuple[bytes, bytes]:
    """Encapsula un shared secret. Retorna (capsule, shared_secret)."""
    ...

def decapsulate(
    capsule: bytes,
    secret_key: bytes,
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> bytes:
    """Desencapsula el shared secret."""
    ...

# --- Funciones hibridas ---

def encrypt_hybrid(
    recipient_public_key: bytes,
    plaintext: bytes,
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> bytes:
    """Cifra con esquema hibrido ML-KEM + AES-256-GCM."""
    ...

def decrypt_hybrid(
    encrypted_package: bytes,
    secret_key: bytes,
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> bytes:
    """Descifra un Transit Package."""
    ...
