import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { VerdictStatus } from "@/lib/types";
import { CHART_COLORS } from "@/lib/colors";

interface VerdictDonutProps {
  counts: Record<VerdictStatus, number>;
}

const ORDER: VerdictStatus[] = ["PASS", "FAIL", "PARTIAL", "INCONCLUSIVE"];
const COLOR_BY_STATUS: Record<VerdictStatus, string> = {
  PASS: CHART_COLORS.pass,
  FAIL: CHART_COLORS.critical,
  PARTIAL: CHART_COLORS.medium,
  INCONCLUSIVE: CHART_COLORS.inconclusive,
};

export function VerdictDonut({ counts }: VerdictDonutProps) {
  const data = ORDER.map((status) => ({ status, value: counts[status] ?? 0 })).filter(
    (entry) => entry.value > 0,
  );
  const total = data.reduce((sum, entry) => sum + entry.value, 0);

  if (total === 0) {
    return (
      <div className="flex h-56 items-center justify-center text-sm text-[var(--color-text-muted)]">
        No verdicts yet
      </div>
    );
  }

  return (
    <div className="relative h-56">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="status"
            innerRadius={62}
            outerRadius={88}
            paddingAngle={3}
            strokeWidth={0}
          >
            {data.map((entry) => (
              <Cell key={entry.status} fill={COLOR_BY_STATUS[entry.status]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: CHART_COLORS.surfaceRaised,
              border: `1px solid ${CHART_COLORS.border}`,
              borderRadius: 8,
              fontSize: 12,
              fontFamily: "JetBrains Mono, monospace",
            }}
            itemStyle={{ color: "#f2f3f5" }}
            labelStyle={{ color: "#a7adb8" }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono-tabular text-2xl font-semibold text-[var(--color-text)]">{total}</span>
        <span className="text-xs text-[var(--color-text-muted)]">verdicts</span>
      </div>
    </div>
  );
}
