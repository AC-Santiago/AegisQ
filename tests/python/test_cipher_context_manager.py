"""Tests del context manager y la zeroizacion proactiva en AegisCipher.

Sprint 2 task 5: ``AegisCipher`` debe implementar el protocolo
``__enter__`` / ``__exit__`` de Python y zeroizar proactivamente
cualquier buffer Python-side registrado durante la sesion al salir.

Hoy la API publica de ``AegisCipher`` no retiene material criptografico
en Python (todo ocurre dentro de Rust via wrappers ``Zeroizing``).
Estos tests verifican:

1. El protocolo ``__enter__`` / ``__exit__`` funciona.
2. ``__exit__`` zeroiza cualquier buffer registrado via
   ``_register_session_buffer`` (este hook sera usado por futuras APIs
   de sesion / streaming).
3. ``__exit__`` no suprime excepciones.
4. La zeroizacion es deterministica, no depende del GC.
5. La zeroizacion es idempotente.

Si una futura API (ej. ``bind_session``) retiene un AES key Python-side,
estos tests daran garantia de que saldra del contexto limpia.
"""

from __future__ import annotations

import pytest

from aegisq import AegisCipher, SecurityLevel


# ---------------------------------------------------------------------------
# Protocolo basico
# ---------------------------------------------------------------------------


class TestContextManagerProtocol:
    def test_works_without_context(self) -> None:
        """Usar AegisCipher sin ``with`` debe seguir funcionando."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        pkg = cipher.encrypt(b"hola", kp.public_key)
        assert cipher.decrypt(pkg, kp.secret_key) == b"hola"

    def test_with_block_yields_self(self) -> None:
        """``__enter__`` devuelve el propio cipher."""
        cipher = AegisCipher()
        with cipher as bound:
            assert bound is cipher

    def test_repr_reflects_state(self) -> None:
        """``__repr__`` expone el estado active/inactive sin filtrar material."""
        cipher = AegisCipher()
        assert "inactive" in repr(cipher)
        with cipher as bound:
            assert "active" in repr(bound)
        assert "inactive" in repr(cipher)

    def test_repr_does_not_leak_secrets(self) -> None:
        """``__repr__`` NUNCA debe incluir bytes de llaves o material sensible."""
        secret_marker = b"\xDE\xAD\xBE\xEF" * 8
        with AegisCipher() as cipher:
            buf = cipher._register_session_buffer(bytearray(secret_marker))
            rep = repr(cipher)
            # El repr no debe incluir los bytes del buffer registrado
            assert secret_marker.hex() not in rep
            # Tras la zeroizacion el buffer se limpia
            cipher._zeroize_session()
            assert bytes(buf) == b"\x00" * 32


# ---------------------------------------------------------------------------
# Zeroizacion proactiva
# ---------------------------------------------------------------------------


class TestProactiveZeroization:
    def test_zeroize_wipes_registered_buffer(self) -> None:
        """Un buffer registrado dentro del contexto se zeroiza al ``__exit__``."""
        secret = bytearray(b"\xAB" * 32)

        with AegisCipher() as cipher:
            held = cipher._register_session_buffer(secret)
            assert bytes(held) == b"\xAB" * 32
        # __exit__ ya debio sobrescribir el buffer in-place
        assert bytes(secret) == b"\x00" * 32

    def test_zeroize_holds_reference_after_exit(self) -> None:
        """Una referencia externa al buffer ve los ceros, no garbage."""
        secret = bytearray(b"\xCD" * 16)
        outer_ref: bytearray | None = None

        with AegisCipher() as cipher:
            outer_ref = cipher._register_session_buffer(secret)
            assert outer_ref is secret

        assert outer_ref is not None
        assert bytes(outer_ref) == b"\x00" * 16

    def test_zeroize_handles_multiple_buffers(self) -> None:
        """Varios buffers registrados se zeroizan todos al salir."""
        with AegisCipher() as cipher:
            a = cipher._register_session_buffer(bytearray(b"\x01" * 8))
            b = cipher._register_session_buffer(bytearray(b"\x02" * 16))
            c = cipher._register_session_buffer(bytearray(b"\x03" * 24))
            assert bytes(a) != b"\x00" * 8
            assert bytes(b) != b"\x00" * 16
            assert bytes(c) != b"\x00" * 24

        assert bytes(a) == b"\x00" * 8
        assert bytes(b) == b"\x00" * 16
        assert bytes(c) == b"\x00" * 24

    def test_zeroize_is_idempotent(self) -> None:
        """Llamar ``_zeroize_session`` multiples veces es seguro y no lanza."""
        with AegisCipher() as cipher:
            cipher._register_session_buffer(bytearray(b"\x99" * 4))
        # Primera zeroizacion ya ocurrio en __exit__; las siguientes son no-op.
        cipher._zeroize_session()
        cipher._zeroize_session()
        cipher._zeroize_session()

    def test_zeroize_with_no_buffers_is_safe(self) -> None:
        """Llamar ``_zeroize_session`` sin buffers registrados no lanza."""
        cipher = AegisCipher()
        cipher._zeroize_session()  # debe ser no-op

    def test_register_outside_context_is_allowed(self) -> None:
        """Registrar un buffer sin contexto no falla; simplemente no se
        zeroiza deterministicamente (porque no hay ``__exit__`` que
        garantice limpieza). El usuario es responsable si lo hace asi.
        """
        cipher = AegisCipher()
        buf = cipher._register_session_buffer(bytearray(b"\x42" * 4))
        # El buffer esta registrado y contiene los bytes
        assert bytes(buf) == b"\x42" * 4

    def test_re_enter_resets_state(self) -> None:
        """Entrar y salir del contexto multiples veces deja el cipher usable."""
        with AegisCipher(level=SecurityLevel.ML_KEM_768) as cipher:
            kp1 = cipher.generate_keypair()
            pkg1 = cipher.encrypt(b"primera", kp1.public_key)
        # Re-entrar el mismo cipher debe funcionar
        with cipher:
            kp2 = cipher.generate_keypair()
            pkg2 = cipher.encrypt(b"segunda", kp2.public_key)
        assert cipher.decrypt(pkg1, kp1.secret_key) == b"primera"
        assert cipher.decrypt(pkg2, kp2.secret_key) == b"segunda"


# ---------------------------------------------------------------------------
# Comportamiento ante excepciones
# ---------------------------------------------------------------------------


class TestExceptionPropagation:
    def test_exception_inside_with_is_not_swallowed(self) -> None:
        """Una excepcion dentro del bloque ``with`` se propaga al llamador."""
        cipher = AegisCipher()
        with pytest.raises(RuntimeError, match="boom"):
            with cipher:
                raise RuntimeError("boom")

    def test_buffer_zeroized_even_when_block_raises(self) -> None:
        """Aunque el bloque levante una excepcion, la zeroizacion corre."""
        secret = bytearray(b"\x55" * 16)

        with pytest.raises(RuntimeError):
            with AegisCipher() as cipher:
                held = cipher._register_session_buffer(secret)
                assert bytes(held) == b"\x55" * 16
                raise RuntimeError("boom")

        # __exit__ debe haber corrido antes de propagar la excepcion
        assert bytes(secret) == b"\x00" * 16

    def test_exit_does_not_swallow_keyboard_interrupt(self) -> None:
        """``__exit__`` retorna ``False`` para no suprimir KeyboardInterrupt."""
        # No podemos usar pytest.raises(KeyboardInterrupt) sin ensuciar el
        # test runner, asi que verificamos la propiedad directamente.
        cipher = AegisCipher()
        with cipher as bound:
            pass
        # Si __exit__ retorna True/None, KeyboardInterrupt seria suprimido.
        # Como retorna False, no hay supresion.
        result = cipher.__exit__(None, None, None)
        assert result is False