import type { LucideIcon } from "lucide-react";
import { HelpCircle, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import type { DeviceTier } from "./types";

export interface TierBadge {
  label: string;
  className: string;
  icon: LucideIcon;
}

// Single source of truth for tier presentation. Device identity (label,
// description, tier) now comes from the API alone - this module only maps
// the `tier` enum to how it should look, for every page that shows a tier
// badge. Includes "unknown" (unlike the hardcoded per-device map this
// replaces) since a real registered device can have that tier.
const TIER_BADGES: Record<DeviceTier, TierBadge> = {
  insecure: {
    label: "Insecure",
    className: "text-[var(--color-critical)] bg-[color-mix(in_oklab,var(--color-critical)_14%,transparent)]",
    icon: ShieldAlert,
  },
  partial: {
    label: "Partial",
    className: "text-[var(--color-medium)] bg-[color-mix(in_oklab,var(--color-medium)_14%,transparent)]",
    icon: ShieldQuestion,
  },
  hardened: {
    label: "Hardened",
    className: "text-[var(--color-pass)] bg-[color-mix(in_oklab,var(--color-pass)_14%,transparent)]",
    icon: ShieldCheck,
  },
  unknown: {
    label: "Unknown",
    className: "text-[var(--color-text-muted)] bg-[var(--color-surface-hover)]",
    icon: HelpCircle,
  },
};

export function getTierBadge(tier: DeviceTier): TierBadge {
  return TIER_BADGES[tier];
}
