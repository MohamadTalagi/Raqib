import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DeviceSummary } from "@/lib/types";
import { CHART_COLORS } from "@/lib/colors";

export function DeviceActivityBar({ devices }: { devices: DeviceSummary[] }) {
  const data = devices.map((device) => ({
    name: device.device_id.replace("device-", "").replace("mqtt-broker-", "mqtt-"),
    evidence: device.evidence_count,
    verdicts: device.verdict_count,
  }));

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 8, left: -16, bottom: 0 }} barGap={4}>
          <CartesianGrid vertical={false} stroke={CHART_COLORS.border} />
          <XAxis
            dataKey="name"
            stroke={CHART_COLORS.textMuted}
            tick={{ fontSize: 11, fontFamily: "JetBrains Mono, monospace" }}
            tickLine={false}
            axisLine={{ stroke: CHART_COLORS.border }}
          />
          <YAxis
            stroke={CHART_COLORS.textMuted}
            tick={{ fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
          />
          <Tooltip
            cursor={{ fill: "rgba(255,255,255,0.03)" }}
            contentStyle={{
              background: CHART_COLORS.surfaceRaised,
              border: `1px solid ${CHART_COLORS.border}`,
              borderRadius: 8,
              fontSize: 12,
            }}
            itemStyle={{ color: "#f2f3f5" }}
            labelStyle={{ color: "#a7adb8", fontFamily: "JetBrains Mono, monospace" }}
          />
          <Bar dataKey="evidence" name="Evidence" fill={CHART_COLORS.low} radius={[4, 4, 0, 0]} maxBarSize={28} />
          <Bar dataKey="verdicts" name="Verdicts" fill={CHART_COLORS.brand} radius={[4, 4, 0, 0]} maxBarSize={28} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
