# ERR-018 — `erasableSyntaxOnly` rejects TypeScript parameter-property shorthand

- **Date:** 2026-07-09
- **Component:** lab/auditor/web (new React dashboard)
- **Severity:** low
- **Status:** resolved
- **Author:** Claude Code session

## What happened
While scaffolding the new React/Vite dashboard (replacing the Flutter `auditor-web`),
`npx tsc -b --noEmit` failed on `src/lib/api.ts` with a custom `ApiError` class using
the common constructor-parameter-property shorthand:

```ts
export class ApiError extends Error {
  constructor(message: string, public readonly status: number) { ... }
}
```

## Exact error / symptom
```
src/lib/api.ts(15,5): error TS1294: This syntax is not allowed when 'erasableSyntaxOnly' is enabled.
```

## Environment
- OS / shell: Windows, PowerShell 5.1 / Git Bash
- Tool + version: TypeScript ~6.0.2 (Vite's `react-ts` template), Node 22
- Relevant files: `lab/auditor/web/src/lib/api.ts`, `lab/auditor/web/tsconfig.app.json`

## Root cause
Vite's current `react-ts` template enables `erasableSyntaxOnly` in
`tsconfig.app.json`, a strict mode where the compiler refuses any TS syntax whose
erasure isn't purely type-level. Constructor parameter properties
(`public readonly status: number`) actually **emit** an assignment
(`this.status = status`), so they aren't erasable — the flag exists to guarantee
`.ts` files can be stripped to `.js` by deleting types only, with no codegen surprises.

## The fix
Rewrote the class to declare the field and assign it explicitly in the constructor
body instead of using parameter-property shorthand:

```ts
export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}
```

## How to prevent it next time
When scaffolding a fresh Vite `react-ts` project, assume `erasableSyntaxOnly` is on
and avoid parameter-property shorthand, `enum`, and other non-erasable TS features
in new code — write the explicit field + assignment form from the start.

## References
None.
