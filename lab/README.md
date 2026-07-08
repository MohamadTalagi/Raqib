# KAUST IoT Security Lab

A Dockerized 3-posture smart-camera lab (insecure / partially hardened / hardened) plus a
manual-assessment toolbox, used to produce evidence for Saudi NCA (CGIoT-1:2024) policy verdicts.

## Prerequisites
- Docker Desktop with Compose v2 (verified: Docker 29.x, Compose v5 on the build PC).
- Run everything from this `lab/` directory.

## First-time setup (once per clone)

```
docker compose --profile init run --rm cert-init
docker run --rm -v kaust-iot-lab_mqtt-secure-passwd:/mosquitto/config eclipse-mosquitto:2 mosquitto_passwd -c -b /mosquitto/config/passwd labworker "LabWork3r-Secr3t!"
docker run --rm -v kaust-iot-lab_mqtt-secure-passwd:/mosquitto/config alpine chmod 644 /mosquitto/config/passwd
```

## Start the lab

```
docker compose up -d --build
docker compose ps    # wait until all services report healthy
```

## Stop the lab

```
docker compose down
```

## Notes
- No device or broker port is published to the host by default — everything is reachable only
  from inside `audit-network`/`internal-network`, matching the training brief. Use
  `docker compose -f docker-compose.yml -f docker-compose.dev.yml up` if you want `device-insecure`
  and `mqtt-broker-insecure` exposed to `localhost` for manual poking around.
- To probe the lab from the audit network without a published port, run a throwaway container
  attached to it, e.g.:
  `docker run --rm --network kaust-iot-lab_audit-network nicolaka/netshoot nmap -sV device-insecure`
- All "insecure" behavior (default creds, hardcoded API key, plaintext MQTT, unsigned firmware) is
  an intentional training fixture inside this sandboxed, non-internet-facing lab.
