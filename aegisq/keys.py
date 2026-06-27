"""Utilidades de serializacion y persistencia de llaves ML-KEM (v1.3.0).

Provee helpers de alto nivel para exportar/importar llaves desde/hacia
disco, variables de entorno y bytes en memoria.

La llave privada **nunca** se exporta en texto plano: se cifra con
AES-256-GCM usando una clave derivada de una contrasena via HKDF-SHA3-256.

Formatos soportados:

* **Llave publica** — PEM-like ``-----BEGIN ML-KEM PUBLIC KEY-----`` (default)
  o JSON con campos ``algorithm``/``level``/``public_key``.
* **Llave privada** — PEM-like ``-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----``
  con blob binario cifrado (Base64 STANDARD en el cuerpo).

Ejemplo basico::

    from aegisq import AegisCipher, SecurityLevel
    from aegisq.keys import save_public_key, load_public_key, save_secret_key, load_secret_key

    cipher = AegisCipher()
    keypair = cipher.generate_keypair()

    # Guardar en disco
    save_public_key(keypair, "recipient.pem")
    save_secret_key(keypair, "private.key", password=b"s3cr3t")

    # Cargar desde disco
    pub_key = load_public_key("recipient.pem")
    sec_key = load_secret_key("private.key", password=b"s3cr3t")

    # Usar
    package = cipher.encrypt(b"datos secretos", pub_key)
    plaintext = cipher.decrypt(package, sec_key)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from aegisq._aegisq_core import (
    KeyPair,
    SecurityLevel,
    load_public_key_json,
    load_public_key_pem,
    load_secret_key_pem,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "save_public_key",
    "load_public_key",
    "save_secret_key",
    "load_secret_key",
    "public_key_to_pem",
    "public_key_to_json",
    "secret_key_to_pem",
]


def save_public_key(
    keypair: KeyPair,
    path: str | Path,
    *,
    fmt: str = "pem",
) -> None:
    """Guarda la llave publica en disco.

    Args:
        keypair: El ``KeyPair`` del cual exportar la llave publica.
        path: Ruta del archivo destino. Se recomienda extension ``.pem``
              para PEM o ``.json`` para JSON.
        fmt: Formato de salida. ``"pem"`` (default) o ``"json"``.

    Raises:
        ValueError: Si ``fmt`` no es ``"pem"`` ni ``"json"``.
        OSError: Si no se puede escribir el archivo.
    """
    if fmt == "pem":
        content = keypair.public_key_pem()
    elif fmt == "json":
        content = keypair.public_key_json()
    else:
        raise ValueError(f"fmt must be 'pem' or 'json', got {fmt!r}")
    Path(path).write_text(content, encoding="utf-8")


def load_public_key(
    path: str | Path,
    *,
    level: SecurityLevel | None = None,
) -> bytes:
    """Carga una llave publica desde disco.

    Detecta automaticamente el formato (PEM o JSON) por la primera linea
    del archivo. Si es JSON, el nivel se extrae del campo ``"level"`` y
    el parametro ``level`` es ignorado.

    Args:
        path: Ruta del archivo.
        level: Nivel de seguridad ML-KEM esperado. **Obligatorio** para
               archivos PEM (no se puede inferir del contenido). Para
               JSON se ignora y se usa el campo ``"level"``.

    Returns:
        bytes: La llave publica lista para pasar a ``AegisCipher.encrypt()``.

    Raises:
        ValueError: Si el formato del archivo no es reconocible o si
                    ``level`` no se proporciono para un PEM.
        KeySerializationError: Si el PEM/JSON esta malformado.
        InvalidParameterError: Si el tamano no coincide con el nivel.
        OSError: Si no se puede leer el archivo.
    """
    text = Path(path).read_text(encoding="utf-8")
    # Detectar formato por la primera linea no vacia.
    first_line = next(
        (ln for ln in text.splitlines() if ln.strip()),
        "",
    )
    if first_line.startswith("-----BEGIN ML-KEM PUBLIC KEY-----"):
        if level is None:
            raise ValueError(
                "level es obligatorio para cargar archivos PEM "
                "(no se puede inferir del contenido)"
            )
        return load_public_key_pem(text, level)
    if first_line.startswith("{"):
        pk_bytes, _ = load_public_key_json(text)
        return pk_bytes
    raise ValueError(
        f"Formato de archivo no reconocible: primera linea = {first_line!r}"
    )


def save_secret_key(
    keypair: KeyPair,
    path: str | Path,
    *,
    password: bytes,
) -> None:
    """Cifra y guarda la llave privada en disco en formato PEM ENCRYPTED.

    La llave **NUNCA** se escribe en texto plano: se cifra con
    AES-256-GCM + HKDF-SHA3-256(``password``).

    Args:
        keypair: El ``KeyPair`` del cual exportar la llave privada.
        path: Ruta del archivo destino. Se recomienda extension ``.key``.
        password: Contrasena para derivar la clave de cifrado.

    Raises:
        RngError: Si el CSPRNG del OS no esta disponible.
        OSError: Si no se puede escribir el archivo.
    """
    content = keypair.export_secret_key_pem(password)
    Path(path).write_text(content, encoding="utf-8")


def load_secret_key(
    path: str | Path,
    *,
    password: bytes,
) -> bytes:
    """Descifra y carga la llave privada desde disco.

    Args:
        path: Ruta del archivo PEM ENCRYPTED.
        password: Contrasena usada al guardar.

    Returns:
        bytes: La llave secreta lista para pasar a
               ``MlKem.decapsulate()`` o ``AegisCipher.decrypt()``.

    Raises:
        DecryptionError: Si la contrasena es incorrecta o el archivo esta corrupto.
        KeySerializationError: Si el PEM/Base64/magic son invalidos.
        OSError: Si no se puede leer el archivo.
    """
    text = Path(path).read_text(encoding="utf-8")
    sk_bytes, _ = load_secret_key_pem(text, password)
    return sk_bytes


def public_key_to_pem(keypair: KeyPair) -> str:
    """Convierte la llave publica de un ``KeyPair`` a formato PEM-like ML-KEM.

    Equivalente a ``keypair.public_key_pem()``, expuesto aqui para
    conveniencia de import.
    """
    return keypair.public_key_pem()


def public_key_to_json(keypair: KeyPair) -> str:
    """Convierte la llave publica de un ``KeyPair`` a formato JSON.

    Equivalente a ``keypair.public_key_json()``, expuesto aqui para
    conveniencia de import.
    """
    return keypair.public_key_json()


def secret_key_to_pem(keypair: KeyPair, *, password: bytes) -> str:
    """Exporta la llave privada cifrada como string PEM ENCRYPTED.

    Equivalente a ``keypair.export_secret_key_pem(password)``, expuesto
    aqui para conveniencia de import.
    """
    return keypair.export_secret_key_pem(password)
