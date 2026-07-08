# Trust Boundaries — Phases 0-5

```mermaid
flowchart LR
    subgraph Untrusted["UNTRUSTED: audit-network"]
        D[3 device profiles + telnet-sim + 2 MQTT brokers]
    end
    subgraph Bridge["ONE-WAY BRIDGE"]
        W[auditor-worker<br/>the only dual-homed container]
    end
    subgraph Trusted["TRUSTED: internal-network (internal: true, no default route)"]
        S[document-store<br/>filesystem, Phases 0-5]
    end

    D -.->|worker PULLS evidence, never pushed inbound| W
    W -->|worker WRITES evidence.json / verdict.json| S
    S -.->|devices have NO route here| D
```

## Rules enforced

1. Devices cannot reach `internal-network` at all — it is a Docker `internal: true` network with no
   gateway to anything devices are attached to.
2. `auditor-worker` never accepts inbound connections from devices; it only initiates outbound
   probes (nmap/curl/mosquitto_sub/openssl) against them.
3. Only `auditor-worker`'s own filesystem writes reach `document-store` — devices cannot write
   evidence, only be evidence *about*.
4. No device port is published to the PC host — the only host-facing service in the full platform
   (Phase 6-8) is `auditor-web`.
