# AegisQ Agents Hub

Este es el hub local de agentes para AegisQ.

## Fuente de verdad

- [AGENTS.md](../AGENTS.md) — reglas canónicas, arquitectura y convenciones.
- [skills/index.md](skills/index.md) — índice humano de skills locales.
- `../.atl/skill-registry.md` — registry local generado, ignorado por Git;
  puede no existir en un checkout nuevo.

## Estado actual

Ver `skills/index.md` para el mapa compacto de skills instaladas.

## Reglas

- No copies `SKILL.md` externos acá.
- Para trabajo nuevo en Python, preferí `python-testing-patterns`.
- Si agregás o quitás skills, refrescá `skills/index.md` y regenerá `../.atl/skill-registry.md`.

## Comandos útiles

```bash
npx skills ls --json
npx skills add owner/repo@skill-name --copy -y
npx skills remove <skill-name> -y
```
