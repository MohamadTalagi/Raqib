import type { LucideIcon } from "lucide-react";
import { Waypoints, Radar, ServerCog, Database, HardDrive } from "lucide-react";
import { serviceIcon } from "@/lib/serviceIcons";
import { cn } from "@/lib/utils";
import type { Device, DeviceTier } from "@/lib/types";

const TIER_COLOR: Record<DeviceTier, string> = {
  hardened: "var(--color-pass)",
  partial: "var(--color-medium)",
  insecure: "var(--color-critical)",
  unknown: "var(--color-inconclusive)",
};

export const TIER_LABEL: Record<DeviceTier, string> = {
  hardened: "Hardened",
  partial: "Partially hardened",
  insecure: "Insecure",
  unknown: "Unknown",
};

const INFRA_COLOR = "var(--color-low)";

/**
 * The two Docker networks this lab actually runs on (see lab/docker-compose.yml):
 * every device sits on audit-network; auditor-api/database are internal-network
 * only ("no route out"); auditor-worker is the one service with a leg in both,
 * since it polls auditor-api over HTTP and also runs collector commands
 * against devices. This is real topology, not a decorative layout.
 */
export interface InfraNode {
  id: string;
  label: string;
  description: string;
  icon: LucideIcon;
  zone: "audit" | "backend";
}

export const INFRA_NODES: InfraNode[] = [
  {
    id: "auditor-worker",
    label: "auditor-worker",
    description:
      "Polls auditor-api for pending scan jobs and is the only process that runs a real collector command (nmap/curl/openssl/mosquitto_sub/tcpdump) against a device. The only service with a leg in both networks.",
    icon: Waypoints,
    zone: "audit",
  },
  {
    id: "traffic-capture",
    label: "traffic-capture",
    description: "Runs tcpdump on the audit network and writes .pcap files to document-store/pcap/.",
    icon: Radar,
    zone: "audit",
  },
  {
    id: "auditor-api",
    label: "auditor-api",
    description:
      "FastAPI REST API for devices, evidence, verdicts, controls and NCA compliance. Internal-network only — no route out.",
    icon: ServerCog,
    zone: "backend",
  },
  {
    id: "auditor-database",
    label: "auditor-database",
    description: "PostgreSQL. Stores devices, assessments, evidence and verdicts. Reachable only from auditor-api and auditor-worker.",
    icon: Database,
    zone: "backend",
  },
];

function shortLabel(deviceId: string): string {
  return deviceId.replace("device-", "").replace("mqtt-broker-", "mqtt-");
}

/** Deterministic 0..1 pseudo-random value from a string, so layout is stable
 * across re-renders instead of reshuffling on every fetch. */
function hashUnit(seed: string): number {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 10000) / 10000;
}

interface ScatterPoint {
  id: string;
  x: number;
  y: number;
}

const VIEW_W = 1000;
const BASE_VIEW_H = 560;
const PAD = 70;
// The minimum amount of space (in viewBox units) any single node is
// guaranteed to have to itself. Grid dimensions grow (more rows) to fit
// however many ids are given rather than packing more nodes into a
// fixed-size area - so unlike rejection-sampling a random position, this
// can never fail to find room and can never place two nodes on top of
// each other, regardless of how many devices get registered.
const CELL_SIZE = 140;
const ZONE_GAP = 40;
const ZONE_TOP_MARGIN = 56;
const AUDIT_ZONE_END = 640;
const BACKEND_ZONE_START = AUDIT_ZONE_END + ZONE_GAP;

interface GridPlacement {
  points: ScatterPoint[];
  rows: number;
}

/** Tiles [xMin,xMax] starting at yMin into a grid sized to give every id its
 * own cell (cols chosen to fit the zone's width at CELL_SIZE, rows however
 * many that requires), then jitters each id within its own cell - bounded
 * well inside the cell's margins so neighboring cells' jitter can never
 * overlap. This guarantees zero collisions by construction: growing the
 * node count grows the grid, not the crowding, so every device keeps its
 * own space no matter how many get added. */
function gridPlacement(ids: string[], xMin: number, xMax: number, yMin: number): GridPlacement {
  if (ids.length === 0) return { points: [], rows: 0 };
  const width = xMax - xMin;
  const cols = Math.max(1, Math.floor(width / CELL_SIZE));
  const rows = Math.ceil(ids.length / cols);
  const cellW = width / cols;
  const jitterFrac = 0.3;

  // Ordered by hash rather than input order, so the layout still reads as
  // semi-random rather than a literal left-to-right/top-to-bottom list.
  const ordered = [...ids].sort((a, b) => hashUnit(`order:${a}`) - hashUnit(`order:${b}`));

  const points = ordered.map((id, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const cx = xMin + cellW * (col + 0.5);
    const cy = yMin + CELL_SIZE * (row + 0.5);
    const jx = (hashUnit(`${id}:x`) - 0.5) * cellW * jitterFrac;
    const jy = (hashUnit(`${id}:y`) - 0.5) * CELL_SIZE * jitterFrac;
    return { id, x: cx + jx, y: cy + jy };
  });

  return { points, rows };
}

/** Prim's algorithm: connects every node in the group with the shortest
 * possible set of edges and no cycles, so branch degree follows real spatial
 * proximity within its own network zone instead of a fixed shape. */
function minimumSpanningTree(points: ScatterPoint[]): Array<[ScatterPoint, ScatterPoint]> {
  if (points.length < 2) return [];
  const inTree = new Set([points[0].id]);
  const byId = new Map(points.map((p) => [p.id, p]));
  const edges: Array<[ScatterPoint, ScatterPoint]> = [];

  while (inTree.size < points.length) {
    let best: { a: ScatterPoint; b: ScatterPoint; d: number } | null = null;
    for (const a of points) {
      if (!inTree.has(a.id)) continue;
      for (const b of points) {
        if (inTree.has(b.id)) continue;
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (!best || d < best.d) best = { a, b, d };
      }
    }
    if (!best) break;
    inTree.add(best.b.id);
    edges.push([byId.get(best.a.id)!, byId.get(best.b.id)!]);
  }
  return edges;
}

/** Quadratic bezier path bowed sideways by `bow` px so links curve instead
 * of running as dead-straight lines. */
function curvedPath(x1: number, y1: number, x2: number, y2: number, bow: number): string {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const len = Math.hypot(dx, dy) || 1;
  const nx = -dy / len;
  const ny = dx / len;
  const cx = mx + nx * bow;
  const cy = my + ny * bow;
  return `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;
}

interface NetworkGraphProps {
  devices: Device[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export function NetworkGraph({ devices, selectedId, onSelect }: NetworkGraphProps) {
  const deviceById = new Map(devices.map((d) => [d.device_id, d]));
  const auditInfra = INFRA_NODES.filter((n) => n.zone === "audit");
  const backendInfra = INFRA_NODES.filter((n) => n.zone === "backend");

  const auditIds = [...devices.map((d) => d.device_id), ...auditInfra.map((n) => n.id)];
  const auditGrid = gridPlacement(auditIds, PAD, AUDIT_ZONE_END, PAD);
  const backendGrid = gridPlacement(backendInfra.map((n) => n.id), BACKEND_ZONE_START, VIEW_W - PAD, PAD);
  const auditPoints = auditGrid.points;
  const backendPoints = backendGrid.points;

  // The canvas grows to fit whichever zone needs more rows, rather than
  // clipping node placement to a fixed height - see gridPlacement's own
  // comment for why this is what actually prevents overlap as devices are
  // added, not just a cosmetic choice.
  const contentRows = Math.max(auditGrid.rows, backendGrid.rows, 1);
  const VIEW_H = Math.max(BASE_VIEW_H, contentRows * CELL_SIZE + 2 * PAD);

  const allPoints = [...auditPoints, ...backendPoints];
  const pointById = new Map(allPoints.map((p) => [p.id, p]));
  const meshEdges = [...minimumSpanningTree(auditPoints), ...minimumSpanningTree(backendPoints)];
  const bridge = pointById.get("auditor-worker")!;
  const apiPoint = pointById.get("auditor-api")!;

  function colorFor(id: string): string {
    const device = deviceById.get(id);
    if (device) return TIER_COLOR[device.tier];
    return INFRA_COLOR;
  }

  return (
    <div
      className="relative w-full overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]"
      style={{ aspectRatio: `${VIEW_W} / ${VIEW_H}` }}
    >
      <svg
        className="absolute inset-0 h-full w-full"
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        preserveAspectRatio="none"
      >
        <defs>
          <pattern id="netgrid" width="28" height="28" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="1" fill="var(--color-border)" />
          </pattern>
        </defs>
        <rect x={0} y={0} width={VIEW_W} height={VIEW_H} fill="url(#netgrid)" />

        {/* Zone boundaries — extra top margin gives the label room to sit
            clearly inside the box instead of straddling the border line. */}
        <rect
          x={PAD - 24}
          y={PAD - ZONE_TOP_MARGIN}
          width={AUDIT_ZONE_END - PAD + 48}
          height={VIEW_H - 2 * PAD + ZONE_TOP_MARGIN + 30}
          rx={16}
          fill="none"
          stroke="var(--color-border-strong)"
          strokeDasharray="4 6"
          strokeWidth={1.5}
        />
        <text
          x={PAD - 12}
          y={PAD - ZONE_TOP_MARGIN + 30}
          fill="var(--color-text-secondary)"
          fontSize={20}
          fontWeight={600}
          fontFamily="JetBrains Mono, monospace"
          letterSpacing={1.5}
        >
          AUDIT NETWORK
        </text>
        <rect
          x={BACKEND_ZONE_START - 24}
          y={PAD - ZONE_TOP_MARGIN}
          width={VIEW_W - PAD - BACKEND_ZONE_START + 48}
          height={VIEW_H - 2 * PAD + ZONE_TOP_MARGIN + 30}
          rx={16}
          fill="none"
          stroke="var(--color-border-strong)"
          strokeDasharray="4 6"
          strokeWidth={1.5}
        />
        <text
          x={BACKEND_ZONE_START - 12}
          y={PAD - ZONE_TOP_MARGIN + 30}
          fill="var(--color-text-secondary)"
          fontSize={20}
          fontWeight={600}
          fontFamily="JetBrains Mono, monospace"
          letterSpacing={1.5}
        >
          BACKEND
        </text>

        {/* Cross-network bridge: auditor-worker is the only service with a leg in both networks */}
        <path
          d={curvedPath(bridge.x, bridge.y, apiPoint.x, apiPoint.y, 30)}
          fill="none"
          stroke="var(--color-brand)"
          strokeWidth={selectedId === "auditor-worker" || selectedId === "auditor-api" ? 3 : 2}
          strokeOpacity={selectedId !== null && selectedId !== "auditor-worker" && selectedId !== "auditor-api" ? 0.2 : 0.75}
          className="transition-[stroke-opacity,stroke-width] duration-300"
        />

        {/* In-zone mesh, based on real spatial adjacency within each network */}
        {meshEdges.map(([a, b]) => {
          const touchesSelected = selectedId !== null && (a.id === selectedId || b.id === selectedId);
          const dimmed = selectedId !== null && !touchesSelected;
          const device = deviceById.get(a.id) ?? deviceById.get(b.id);
          const weight = device ? 1.4 + Math.min(device.evidence_count, 10) * 0.12 : 1.4;
          const bow = (hashUnit(`${a.id}${b.id}:bow`) - 0.5) * 90;
          return (
            <path
              key={`${a.id}-${b.id}`}
              d={curvedPath(a.x, a.y, b.x, b.y, bow)}
              fill="none"
              stroke={colorFor(b.id) === INFRA_COLOR ? colorFor(a.id) : colorFor(b.id)}
              strokeWidth={touchesSelected ? weight + 1 : weight}
              strokeOpacity={dimmed ? 0.15 : 0.55}
              strokeDasharray="5 7"
              className="animate-network-dash transition-[stroke-opacity,stroke-width] duration-300"
            />
          );
        })}
      </svg>

      {/* Infra nodes */}
      {INFRA_NODES.map((infra) => {
        const point = pointById.get(infra.id);
        if (!point) return null;
        const Icon = infra.icon;
        const isSelected = selectedId === infra.id;
        const dimmed = selectedId !== null && !isSelected;
        const xPct = (point.x / VIEW_W) * 100;
        const yPct = (point.y / VIEW_H) * 100;

        return (
          <button
            key={infra.id}
            type="button"
            onClick={() => onSelect(infra.id === selectedId ? "" : infra.id)}
            className={cn(
              "absolute z-10 flex -translate-x-1/2 -translate-y-1/2 cursor-pointer flex-col items-center gap-1.5 transition-all duration-300",
              dimmed ? "opacity-35" : "opacity-100",
            )}
            style={{ left: `${xPct}%`, top: `${yPct}%` }}
          >
            <span
              className="flex h-14 w-14 items-center justify-center rounded-lg border-2 bg-[var(--color-surface)] transition-transform hover:scale-110"
              style={{
                borderColor: INFRA_COLOR,
                boxShadow: isSelected
                  ? `0 0 0 3px color-mix(in oklab, ${INFRA_COLOR} 25%, transparent), 0 0 20px -2px color-mix(in oklab, ${INFRA_COLOR} 70%, transparent)`
                  : `0 0 16px -6px color-mix(in oklab, ${INFRA_COLOR} 60%, transparent)`,
              }}
            >
              <Icon className="h-5 w-5" style={{ color: INFRA_COLOR }} strokeWidth={2} />
            </span>
            <span className="max-w-[7.5rem] truncate rounded bg-[var(--color-bg)]/80 px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">
              {infra.label}
            </span>
          </button>
        );
      })}

      {/* Device nodes */}
      {devices.map((device) => {
        const point = pointById.get(device.device_id);
        if (!point) return null;
        const color = TIER_COLOR[device.tier];
        const Icon = device.services[0] ? serviceIcon(device.services[0].service_type) : HardDrive;
        const isSelected = selectedId === device.device_id;
        const dimmed = selectedId !== null && !isSelected;
        const xPct = (point.x / VIEW_W) * 100;
        const yPct = (point.y / VIEW_H) * 100;

        return (
          <button
            key={device.device_id}
            type="button"
            onClick={() => onSelect(device.device_id === selectedId ? "" : device.device_id)}
            className={cn(
              "absolute z-10 flex -translate-x-1/2 -translate-y-1/2 cursor-pointer flex-col items-center gap-1.5 transition-all duration-300",
              dimmed ? "opacity-35" : "opacity-100",
            )}
            style={{ left: `${xPct}%`, top: `${yPct}%` }}
          >
            <span
              className="flex h-14 w-14 items-center justify-center rounded-full border-2 bg-[var(--color-surface)] transition-transform hover:scale-110"
              style={{
                borderColor: color,
                boxShadow: isSelected
                  ? `0 0 0 3px color-mix(in oklab, ${color} 25%, transparent), 0 0 20px -2px color-mix(in oklab, ${color} 70%, transparent)`
                  : `0 0 16px -6px color-mix(in oklab, ${color} 60%, transparent)`,
              }}
            >
              <Icon className="h-5 w-5" style={{ color }} strokeWidth={2} />
            </span>
            <span
              className="max-w-[7.5rem] truncate rounded bg-[var(--color-bg)]/80 px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]"
              title={device.device_id}
            >
              {shortLabel(device.device_id)}
            </span>
          </button>
        );
      })}
    </div>
  );
}
