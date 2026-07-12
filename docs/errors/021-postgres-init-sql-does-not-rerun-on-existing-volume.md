# ERR-021 — Adding a table to `init.sql` doesn't reach an already-created database

- **Date:** 2026-07-12
- **Component:** lab/auditor/db, lab/auditor/api (new `scan_jobs` table)
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude Code session

## What happened
Added a new `scan_jobs` table to `lab/auditor/db/init.sql` to support the
dashboard's new "Run Scan" feature. Rebuilt and started the local dev stack
with the new `auditor-api` image (which now imports `policies.catalog` and
queries `scan_jobs`). `GET /scan-jobs` immediately failed.

## Exact error / symptom
```
psycopg.errors.UndefinedTable: relation "scan_jobs" does not exist
LINE 1: ...FROM scan_jobs ...
```
`auditor-worker`'s `job_runner.py` logged the same failure every poll cycle
(`500 Server Error` from `GET /scan-jobs?status=pending`).

## Environment
- Docker Compose, `postgres:16-alpine`, named volume `auditor-db-data`
- Relevant files: `lab/auditor/db/init.sql`, `lab/docker-compose.yml`

## Root cause
The official Postgres image only executes `/docker-entrypoint-initdb.d/*.sql`
the **first** time a container starts against an **empty** data directory.
The local `auditor-db-data` volume had already been initialized in an
earlier session (before `scan_jobs` existed in `init.sql`), so rebuilding
`auditor-api`'s image and recreating the container changed the application
code but never touched the already-initialized database — `init.sql`'s new
`CREATE TABLE scan_jobs` line was simply never executed.

## The fix
For local dev, applied the missing DDL directly against the running
container instead of wiping data:
```
docker exec kaust-iot-lab-auditor-database-1 psql -U auditor -d auditor -c "
CREATE TABLE IF NOT EXISTS scan_jobs (...);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
"
```
The same manual step is required on the build PC before the "Run Scan"
feature will work there — its `auditor-db-data` volume predates this table
too. `docker compose build`/`up --force-recreate` alone is **not** enough;
the schema change has to be applied to the existing volume explicitly.

## How to prevent it next time
Adding a table to `init.sql` only affects environments that start from a
fresh volume (a clean clone, or `docker volume rm auditor-db-data`). Any
environment with existing data needs the new DDL run against it directly —
this project has no formal migration tool (e.g. Alembic/Flyway), so for now
that means: after editing `init.sql`, always also run the new
`CREATE TABLE`/`ALTER TABLE` statements by hand against every environment
that already has a populated volume, and say so explicitly in the deploy
notes rather than assuming a rebuild picks it up.

## References
None.
