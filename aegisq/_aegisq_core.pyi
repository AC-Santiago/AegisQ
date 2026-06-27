"""Type stubs para el modulo nativo ``aegisq._aegisq_core``.

Proporciona autocompletado y type checking para IDEs (PyCharm, VS Code)
y herramientas de analisis estatico (mypy, pyright).
"""

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

class KeySerializationError(AegisQError):
    """Invalid key serialization format (PEM header, JSON, magic bytes)."""

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

    def public_key_b64(self) -> str:
        """Retorna la clave publica como Base64 URL-safe sin padding."""
        ...

    def public_key_pem(self) -> str:
        """Retorna la clave publica en formato PEM-like ML-KEM."""
        ...

    def public_key_json(self) -> str:
        """Retorna la clave publica en formato JSON."""
        ...

    def export_secret_key_raw(self, password: bytes) -> bytes:
        """Retorna la clave secreta cifrada como blob binario opaco.

        Usa AES-256-GCM con clave derivada de ``password`` via HKDF-SHA3-256.
        Libera el GIL durante HKDF + AES-GCM.
        """
        ...

    def export_secret_key_pem(self, password: bytes) -> str:
        """Retorna la clave secreta cifrada en formato PEM-like ENCRYPTED."""
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

def serialize_public_key(public_key: bytes) -> str:
    """Serializa una llave publica ML-KEM a Base64 URL-safe sin padding."""
    ...

def deserialize_public_key(
    b64: str,
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> bytes:
    """Deserializa una llave publica desde Base64 URL-safe. Valida el tamano."""
    ...

def generate_keypair_deterministic(
    d: bytes,
    z: bytes,
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> KeyPair:
    """Genera un par de claves ML-KEM usando seeds especificos.

    Version DETERMINISTA para validacion con vectores KAT.
    NO usar en produccion.

    Args:
        d: Seed de 32 bytes para generacion de claves K-PKE.
        z: Seed de 32 bytes para el contenido de la clave secreta.
        level: Nivel de seguridad.

    Returns:
        KeyPair con public_key y secret_key.

    Raises:
        InvalidParameterError: Si los seeds no tienen 32 bytes.
    """
    ...

def encapsulate_deterministic(
    public_key: bytes,
    m: bytes,
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> tuple[bytes, bytes, bytes]:
    """Encapsula un shared secret usando un mensaje especifico.

    Version DETERMINISTA para validacion con vectores KAT.
    NO usar en produccion.

    Args:
        public_key: Clave publica del receptor.
        m: Mensaje de 32 bytes a encapsular.
        level: Nivel de seguridad.

    Returns:
        Tupla (capsule, shared_secret, m).

    Raises:
        InvalidParameterError: Si los parametros tienen tamano incorrecto.
    """
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

# --- Serializacion / carga de llaves (v1.3.0) ---

def load_public_key_pem(
    pem: str,
    level: SecurityLevel = SecurityLevel.ML_KEM_768,
) -> bytes:
    """Carga una llave publica desde formato PEM-like ML-KEM.

    Raises:
        KeySerializationError: Si el PEM no tiene header/footer o Base64 invalido.
        InvalidParameterError: Si el tamano no coincide con el nivel.
    """
    ...

def load_public_key_json(json: str) -> tuple[bytes, SecurityLevel]:
    """Carga una llave publica desde JSON.

    El JSON debe tener los campos ``algorithm``, ``level`` y ``public_key``.

    Returns:
        Tupla ``(public_key_bytes, level)``.

    Raises:
        KeySerializationError: Si el JSON esta malformado o le faltan campos.
        InvalidParameterError: Si el tamano no coincide con el nivel declarado.
    """
    ...

def load_secret_key_raw(
    blob: bytes,
    password: bytes,
) -> tuple[bytes, SecurityLevel]:
    """Descifra y retorna la llave secreta desde un blob binario.

    Raises:
        DecryptionError: Si la contrasena es incorrecta o el blob esta corrupto.
        KeySerializationError: Si magic/version son invalidos o el blob esta truncado.
    """
    ...

def load_secret_key_pem(
    pem: str,
    password: bytes,
) -> tuple[bytes, SecurityLevel]:
    """Descifra y retorna la llave secreta desde un PEM-like ENCRYPTED.

    Raises:
        DecryptionError: Si la contrasena es incorrecta o el blob esta corrupto.
        KeySerializationError: Si el PEM/Base64/magic son invalidos.
    """
    ...
