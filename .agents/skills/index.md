# Skills Index

Mapa compacto de skills locales para agentes. Las rutas son relativas al root del repo.

## Rust core

| Skill | Use when | Path |
|------|----------|------|
| `rust-engineer` | ownership, borrowing, lifetimes, async, clippy | `.agents/skills/rust-engineer/SKILL.md` |

## FFI / unsafe

| Skill | Use when | Path |
|------|----------|------|
| `unsafe-checker` | unsafe, raw pointers, ABI, SAFETY comments, UB review | `.agents/skills/unsafe-checker/SKILL.md` |
| `rust-ffi` | bindgen, cbindgen, extern "C", safe wrappers | `.agents/skills/rust-ffi/SKILL.md` |

## Security

| Skill | Use when | Path |
|------|----------|------|
| `security-auditor` | threat modeling, crypto review, DevSecOps | `.agents/skills/security-auditor/SKILL.md` |

## Python testing

| Skill | Use when | Path |
|------|----------|------|
| `python-testing-patterns` | pytest, fixtures, mocking, async, TDD | `.agents/skills/python-testing-patterns/SKILL.md` |
| `python-testing` | quick/simple pytest cases | `.agents/skills/python-testing/SKILL.md` |

## Load order

- Rust core → `rust-engineer`
- Unsafe/FFI → `unsafe-checker` + `rust-ffi`
- Security/crypto review → `security-auditor`
- New Python tests → `python-testing-patterns`
- Quick fallback → `python-testing`
