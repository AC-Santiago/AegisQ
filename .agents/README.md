# AegisQ Agents Hub

Este es el hub local de agentes para AegisQ.

## Fuente de verdad

- `../AGENTS.md` — reglas canónicas, arquitectura y convenciones.
- `skills/index.md` — índice humano de skills instaladas en scope proyecto.
- `../.atl/skill-registry.md` — registry máquina para delegación.

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
