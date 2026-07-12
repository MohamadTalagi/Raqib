# Lab Architecture — Phases 0-5

![Architecture diagram](architecture-diagram.png)

Rendered image above; Mermaid source below (also renders automatically on GitHub).

```mermaid
flowchart TB
    subgraph HOST["HOST (32GB PC) — only auditor-web published"]
    end

    subgraph INTERNAL["internal-network 172.31.0.0/24 (TRUSTED, internal: true)"]
        WORKER[auditor-worker<br/>dual-homed bridge]
    end

    subgraph AUDIT["audit-network 172.30.0.0/24 (UNTRUSTED simulated IoT LAN)"]
        DI[device-insecure<br/>HTTP:80]
        DP[device-partial<br/>HTTPS weak:443]
        DH[device-hardened<br/>HTTPS strong:443]
        TS[telnet-sim<br/>TCP:23]
        MI[mqtt-broker-insecure<br/>1883 plaintext]
        MS[mqtt-broker-secure<br/>8883 TLS]
    end

    WORKER -->|pulls evidence| DI
    WORKER -->|pulls evidence| DP
    WORKER -->|pulls evidence| DH
    WORKER -->|pulls evidence| TS
    WORKER -->|pulls evidence| MI
    WORKER -->|pulls evidence| MS
    DI -->|plaintext telemetry| MI
    DP -->|plaintext telemetry| MI
    DH -->|TLS telemetry| MS
```

## Containers (Phases 0-5 scope)

| Container | Network(s) | Port | Host-exposed? |
|---|---|---|---|
| device-insecure | audit-network | 80 (HTTP) | no |
| device-partial | audit-network | 443 (weak TLS) | no |
| device-hardened | audit-network | 443 (strong TLS) | no |
| telnet-sim | audit-network | 23 | no |
| mqtt-broker-insecure | audit-network | 1883 | no |
| mqtt-broker-secure | audit-network | 8883 | no |
| auditor-worker | audit-network + internal-network | n/a (toolbox) | no |

`auditor-api`/`auditor-database`/`document-store`(as a service)/`auditor-web` are added in the Phase 6-8 follow-up plan; `document-store` is a plain filesystem directory for Phases 0-5.
