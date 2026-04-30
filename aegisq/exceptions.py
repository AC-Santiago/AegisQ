"""Jerarquia de excepciones de AegisQ.

Importa las excepciones nativas definidas en Rust (via PyO3) y las re-exporta
con documentacion Python. El usuario puede hacer catch especifico o general::

    from aegisq import AegisQError, DecryptionError

    try:
        plaintext = cipher.decrypt(package, secret_key)
    except DecryptionError:
        print("Payload manipulado o clave incorrecta")
    except AegisQError:
        print("Error general de AegisQ")
"""

from aegisq._aegisq_core import (
    AegisQError,
    DecapsulationError,
    DecryptionError,
    InvalidParameterError,
    RngError,
)

__all__ = [
    "AegisQError",
    "DecapsulationError",
    "DecryptionError",
    "InvalidParameterError",
    "RngError",
    "SessionExpiredError",
]


class SessionExpiredError(AegisQError):
    """Lanzada cuando se intenta usar una sesion efimera que ya fue cerrada.

    Ocurre cuando se intenta invocar ``encrypt()`` o ``decrypt()`` en una
    ``EphemeralSession`` despues de que el contexto fue cerrado explicitamente
    via ``close()`` o al salir de un context manager ``with``.
    """
