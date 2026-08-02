import type { LucideIcon } from "lucide-react";
import {
  Globe,
  Lock,
  Radio,
  RadioTower,
  Terminal,
  KeyRound,
  Cpu,
  Video,
  Router,
  Wifi,
} from "lucide-react";
import type { ServiceType } from "./types";

const SERVICE_ICONS: Record<ServiceType, LucideIcon> = {
  http: Globe,
  https: Lock,
  mqtt: Radio,
  mqtts: RadioTower,
  telnet: Terminal,
  ssh: KeyRound,
  modbus: Cpu,
  rtsp: Video,
  upnp: Router,
  mdns: Wifi,
};

export function serviceIcon(serviceType: ServiceType): LucideIcon {
  return SERVICE_ICONS[serviceType] ?? Globe;
}
