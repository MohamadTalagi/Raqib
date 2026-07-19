import type { LucideIcon } from "lucide-react";
import { Globe, Lock, Radio, RadioTower, Terminal, KeyRound } from "lucide-react";
import type { ServiceType } from "./types";

const SERVICE_ICONS: Record<ServiceType, LucideIcon> = {
  http: Globe,
  https: Lock,
  mqtt: Radio,
  mqtts: RadioTower,
  telnet: Terminal,
  ssh: KeyRound,
};

export function serviceIcon(serviceType: ServiceType): LucideIcon {
  return SERVICE_ICONS[serviceType] ?? Globe;
}
