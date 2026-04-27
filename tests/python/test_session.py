"""Tests para EphemeralSession.

Verifica que la sesion efimera funciona correctamente con forward secrecy.
"""

import pytest

from aegisq import EphemeralSession, SecurityLevel
from aegisq.exceptions import DecryptionError, SessionExpiredError


class TestEphemeralSessionBasic:
    """Tests basicos de EphemeralSession."""

    def test_default_level(self) -> None:
        session = EphemeralSession()
        assert session.level == SecurityLevel.ML_KEM_768

    def test_custom_level(self) -> None:
        session = EphemeralSession(level=SecurityLevel.ML_KEM_512)
        assert session.level == SecurityLevel.ML_KEM_512

    def test_repr_open(self) -> None:
        session = EphemeralSession(level=SecurityLevel.ML_KEM_768)
        r = repr(session)
        assert "EphemeralSession" in r
        assert "ML_KEM_768" in r
        assert "open" in r

    def test_repr_closed(self) -> None:
        session = EphemeralSession()
        session.close()
        r = repr(session)
        assert "EphemeralSession" in r
        assert "closed" in r


class TestEphemeralSessionPublicKey:
    """Tests de la propiedad public_key."""

    def test_public_key_returns_bytes(self) -> None:
        session = EphemeralSession()
        assert isinstance(session.public_key, bytes)

    def test_public_key_size_mlkem_768(self) -> None:
        session = EphemeralSession(level=SecurityLevel.ML_KEM_768)
        assert len(session.public_key) == 1184

    def test_public_key_size_mlkem_512(self) -> None:
        session = EphemeralSession(level=SecurityLevel.ML_KEM_512)
        assert len(session.public_key) == 800

    def test_public_key_size_mlkem_1024(self) -> None:
        session = EphemeralSession(level=SecurityLevel.ML_KEM_1024)
        assert len(session.public_key) == 1568

    def test_public_key_immutable(self) -> None:
        """Verifica que public_key retorna una copia, no referencia interna."""
        session = EphemeralSession()
        pk = session.public_key
        pk_copy = bytearray(pk)
        pk_copy[0] ^= 0xFF
        # La clave interna no debe haber cambiado
        assert session.public_key[0] != pk_copy[0]


class TestEphemeralSessionEncryptDecrypt:
    """Tests de cifrado y descifrado con EphemeralSession."""

    def test_roundtrip_same_session(self) -> None:
        """Cifrar y descifrar con la misma sesion."""
        session = EphemeralSession()
        plaintext = b"Forward secrecy test"

        package = session.encrypt(
            plaintext=plaintext,
            recipient_public_key=session.public_key,
        )
        recovered = session.decrypt(package)

        assert recovered == plaintext

    def test_roundtrip_all_levels(self) -> None:
        """Roundtrip para los tres niveles de seguridad."""
        for level in [
            SecurityLevel.ML_KEM_512,
            SecurityLevel.ML_KEM_768,
            SecurityLevel.ML_KEM_1024,
        ]:
            session = EphemeralSession(level=level)
            plaintext = b"Testing level roundtrip"

            package = session.encrypt(
                plaintext=plaintext,
                recipient_public_key=session.public_key,
            )
            recovered = session.decrypt(package)

            assert recovered == plaintext, f"Roundtrip failed for {level}"

    def test_empty_plaintext(self) -> None:
        session = EphemeralSession()
        package = session.encrypt(
            plaintext=b"",
            recipient_public_key=session.public_key,
        )
        recovered = session.decrypt(package)
        assert recovered == b""

    def test_large_payload(self) -> None:
        session = EphemeralSession()
        plaintext = bytes(range(256)) * 1000  # 256 KB

        package = session.encrypt(
            plaintext=plaintext,
            recipient_public_key=session.public_key,
        )
        recovered = session.decrypt(package)

        assert recovered == plaintext

    def test_binary_data(self) -> None:
        """Test with arbitrary binary data including null bytes."""
        session = EphemeralSession()
        plaintext = b"\x00\x01\x02\xff\xfe\xfd" * 100

        package = session.encrypt(
            plaintext=plaintext,
            recipient_public_key=session.public_key,
        )
        recovered = session.decrypt(package)

        assert recovered == plaintext

    def test_different_packages_are_different(self) -> None:
        """Dos cifrados del mismo plaintext producen paquetes distintos."""
        session = EphemeralSession()
        plaintext = b"Same data, different packages"

        p1 = session.encrypt(plaintext=plaintext, recipient_public_key=session.public_key)
        p2 = session.encrypt(plaintext=plaintext, recipient_public_key=session.public_key)

        assert p1 != p2


class TestEphemeralSessionCrossSession:
    """Tests de cifrado entre sesiones distintas (Alice -> Bob)."""

    def test_alice_bob_flow(self) -> None:
        """Flujo canonico: Alice cifra para Bob con su clave publica."""
        # Bob crea una sesion efimera
        bob_session = EphemeralSession()

        # Alice cifra usando la clave publica de Bob
        alice_session = EphemeralSession()
        plaintext = b"Secret message for Bob"
        package = alice_session.encrypt(
            plaintext=plaintext,
            recipient_public_key=bob_session.public_key,
        )

        # Bob descifra con su sesion
        recovered = bob_session.decrypt(package)

        assert recovered == plaintext

    def test_cross_session_decrypt_wrong_key(self) -> None:
        """Un mensaje cifrado para otra sesion no puede ser descifrado."""
        session_alice = EphemeralSession()
        session_bob = EphemeralSession()

        package = session_alice.encrypt(
            plaintext=b"Secret",
            recipient_public_key=session_alice.public_key,
        )

        # Bob intenta descifrar con su propia sesion -> debe fallar
        with pytest.raises(DecryptionError):
            session_bob.decrypt(package)


class TestEphemeralSessionLifecycle:
    """Tests del ciclo de vida de la sesion."""

    def test_context_manager(self) -> None:
        """Uso como context manager cierra automaticamente la sesion."""
        with EphemeralSession() as session:
            plaintext = b"Context manager test"
            package = session.encrypt(
                plaintext=plaintext,
                recipient_public_key=session.public_key,
            )
            recovered = session.decrypt(package)
            assert recovered == plaintext

        # Al salir del with, la sesion debe estar cerrada

    def test_close_method(self) -> None:
        """close() cierra la sesion y destruye la clave."""
        session = EphemeralSession()
        session.close()

        # No se puede usar encrypt
        with pytest.raises(SessionExpiredError):
            session.encrypt(b"data", b"pk")

        # No se puede usar decrypt
        with pytest.raises(SessionExpiredError):
            session.decrypt(b"package")

    def test_close_multiple_times(self) -> None:
        """close() es seguro llamarlo multiples veces."""
        session = EphemeralSession()
        session.close()
        session.close()  # No debe lanzar
        session.close()  # No debe lanzar

    def test_public_key_after_close_raises(self) -> None:
        """public_key levanta SessionExpiredError si se consulta luego de cerrar."""
        session = EphemeralSession()
        session.close()

        with pytest.raises(SessionExpiredError):
            _ = session.public_key

    def test_del_closes_session(self) -> None:
        """__del__ debe cerrar la sesion."""
        session = EphemeralSession()
        pk = session.public_key  # Usamos la sesion

        # Eliminamos la referencia (garbage collection)
        del session

        # Si llegamos aca sin crash, __del__ funciono correctamente


class TestEphemeralSessionErrors:
    """Tests de manejo de errores."""

    def test_wrong_key_raises_decryption_error(self) -> None:
        """Clave incorrecta levanta DecryptionError."""
        session = EphemeralSession()
        wrong_kp = EphemeralSession()

        package = session.encrypt(
            plaintext=b"Wrong key test",
            recipient_public_key=session.public_key,
        )

        with pytest.raises(DecryptionError):
            wrong_kp.decrypt(package)

    def test_tampered_package_raises_decryption_error(self) -> None:
        """Package manipulado levanta DecryptionError."""
        session = EphemeralSession()
        package = session.encrypt(
            plaintext=b"Tamper test",
            recipient_public_key=session.public_key,
        )

        tampered = bytearray(package)
        tampered[-1] ^= 0xFF
        tampered_package = bytes(tampered)

        with pytest.raises(DecryptionError):
            session.decrypt(tampered_package)

    def test_invalid_public_key_raises(self) -> None:
        """Clave publica invalida levanta InvalidParameterError."""
        from aegisq.exceptions import InvalidParameterError

        session = EphemeralSession()
        with pytest.raises(InvalidParameterError):
            session.encrypt(plaintext=b"data", recipient_public_key=b"not_valid")

    def test_decrypt_wrong_session_key_raises(self) -> None:
        """No se puede descifrar con la clave de otra sesion."""
        session_a = EphemeralSession()
        session_b = EphemeralSession()

        package = session_a.encrypt(
            plaintext=b"Secret",
            recipient_public_key=session_a.public_key,
        )

        # session_b no puede descifrar esto porque no tiene la clave correcta
        with pytest.raises(DecryptionError):
            session_b.decrypt(package)
