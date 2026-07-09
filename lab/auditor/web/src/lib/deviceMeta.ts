import type { LucideIcon } from "lucide-react";
import { Camera, Radio, ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";

export type DeviceTier = "insecure" | "partial" | "hardened" | "broker-insecure" | "broker-secure";

interface DeviceMeta {
  label: string;
  description: string;
  tier: DeviceTier;
  icon: LucideIcon;
}

const DEVICE_META: Record<string, DeviceMeta> = {
  "device-insecure": {
    label: "Smart Camera — Insecure",
    description: "Default creds, plain HTTP, Telnet, unencrypted MQTT, hard-coded API key.",
    tier: "insecure",
    icon: Camera,
  },
  "device-partial": {
    label: "Smart Camera — Partially Hardened",
    description: "Telnet removed, HTTPS with a weak cert, MQTT still unencrypted.",
    tier: "partial",
    icon: Camera,
  },
  "device-hardened": {
    label: "Smart Camera — Hardened",
    description: "HTTPS only, strong creds, MQTT over TLS, signed firmware.",
    tier: "hardened",
    icon: Camera,
  },
  "mqtt-broker-insecure": {
    label: "MQTT Broker — Insecure",
    description: "Unauthenticated, plaintext MQTT on port 1883.",
    tier: "broker-insecure",
    icon: Radio,
  },
  "mqtt-broker-secure": {
    label: "MQTT Broker — Secure",
    description: "TLS-only MQTT on port 8883 with certificate auth.",
    tier: "broker-secure",
    icon: Radio,
  },
};

const TIER_STYLES: Record<DeviceTier, { label: string; className: string; icon: LucideIcon }> = {
  insecure: { label: "Insecure", className: "text-[var(--color-critical)] bg-[color-mix(in_oklab,var(--color-critical)_14%,transparent)]", icon: ShieldAlert },
  partial: { label: "Partial", className: "text-[var(--color-medium)] bg-[color-mix(in_oklab,var(--color-medium)_14%,transparent)]", icon: ShieldQuestion },
  hardened: { label: "Hardened", className: "text-[var(--color-pass)] bg-[color-mix(in_oklab,var(--color-pass)_14%,transparent)]", icon: ShieldCheck },
  "broker-insecure": { label: "Insecure", className: "text-[var(--color-critical)] bg-[color-mix(in_oklab,var(--color-critical)_14%,transparent)]", icon: ShieldAlert },
  "broker-secure": { label: "Secure", className: "text-[var(--color-pass)] bg-[color-mix(in_oklab,var(--color-pass)_14%,transparent)]", icon: ShieldCheck },
};

export function getDeviceMeta(deviceId: string): DeviceMeta {
  return (
    DEVICE_META[deviceId] ?? {
      label: deviceId,
      description: "No profile metadata available for this device.",
      tier: "partial",
      icon: Radio,
    }
  );
}

export function getTierBadge(tier: DeviceTier) {
  return TIER_STYLES[tier];
}
