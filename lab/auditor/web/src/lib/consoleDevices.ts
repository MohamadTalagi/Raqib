export interface ConsoleDevice {
  device_id: string;
  scheme: "http" | "https";
  port: number;
}

// Ports match the dev-overlay publishing in docker-compose.dev.yml.
export const CONSOLE_DEVICES: ConsoleDevice[] = [
  { device_id: "device-insecure", scheme: "http", port: 8081 },
  { device_id: "device-partial", scheme: "https", port: 8082 },
  { device_id: "device-hardened", scheme: "https", port: 8083 },
];

export function consoleBaseUrl(device: ConsoleDevice): string {
  return `${device.scheme}://${window.location.hostname}:${device.port}`;
}

export interface ConsoleEndpoint {
  key: string;
  label: string;
  method: "GET" | "POST";
  path: string;
  body?: string;
  contentType?: string;
}

// One button per service the brief requires on the simulated device.
export const CONSOLE_ENDPOINTS: ConsoleEndpoint[] = [
  { key: "login-page", label: "Login page", method: "GET", path: "/" },
  {
    key: "login",
    label: "Login (admin / admin)",
    method: "POST",
    path: "/login",
    body: "username=admin&password=admin",
    contentType: "application/x-www-form-urlencoded",
  },
  { key: "device-info", label: "Device info", method: "GET", path: "/api/device/info" },
  { key: "config", label: "Config", method: "GET", path: "/api/config" },
  { key: "firmware", label: "Firmware version", method: "GET", path: "/api/firmware/version" },
  { key: "admin-reset", label: "Admin reset", method: "GET", path: "/api/admin/reset" },
  { key: "privacy", label: "Privacy doc", method: "GET", path: "/privacy" },
  { key: "health", label: "Health", method: "GET", path: "/health" },
];

export interface ConsoleResult {
  endpointKey: string;
  ok: boolean;
  status: number | null;
  body: string;
  timestamp: Date;
}

export async function callConsoleEndpoint(baseUrl: string, ep: ConsoleEndpoint): Promise<ConsoleResult> {
  const timestamp = new Date();
  try {
    const res = await fetch(baseUrl + ep.path, {
      method: ep.method,
      headers: ep.contentType ? { "Content-Type": ep.contentType } : undefined,
      body: ep.body,
    });
    const text = await res.text();
    let body = text;
    try {
      body = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      // not JSON (the login page and /privacy are HTML/plain text) - show as-is
    }
    return { endpointKey: ep.key, ok: res.ok, status: res.status, body, timestamp };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { endpointKey: ep.key, ok: false, status: null, body: message, timestamp };
  }
}
