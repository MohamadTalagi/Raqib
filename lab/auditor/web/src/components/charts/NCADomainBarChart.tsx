import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { NCADomainSummary } from "@/lib/types";
import { CHART_COLORS } from "@/lib/colors";

interface NCADomainBarChartProps {
  domains: NCADomainSummary;
}

/** Grouped bar chart, one group per CGIoT-1:2024 domain — same recharts +
 * CHART_COLORS + tooltip convention as DeviceActivityBar. */
export function NCADomainBarChart({ domains }: NCADomainBarChartProps) {
  const data = Object.entries(domains).map(([domainName, counts]) => ({
    name: domainName.length > 18 ? `${domainName.slice(0, 17)}…` : domainName,
    fullName: domainName,
    pass: counts.pass,
    partial: counts.partial,
    fail: counts.fail,
    not_tested: counts.not_tested,
    review_required: counts.review_required,
  }));

  if (data.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-[var(--color-text-muted)]">
        No domains loaded.
      </div>
    );
  }

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 8, left: -16, bottom: 0 }} barGap={2}>
          <CartesianGrid vertical={false} stroke={CHART_COLORS.border} />
          <XAxis
            dataKey="name"
            stroke={CHART_COLORS.textMuted}
            tick={{ fontSize: 10, fontFamily: "JetBrains Mono, monospace" }}
            tickLine={false}
            axisLine={{ stroke: CHART_COLORS.border }}
            interval={0}
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
            labelFormatter={(_, payload) => payload?.[0]?.payload?.fullName ?? ""}
          />
          <Legend wrapperStyle={{ fontSize: 11, color: CHART_COLORS.textSecondary }} />
          <Bar dataKey="pass" name="Pass" stackId="s" fill={CHART_COLORS.pass} />
          <Bar dataKey="partial" name="Partial" stackId="s" fill={CHART_COLORS.medium} />
          <Bar dataKey="fail" name="Fail" stackId="s" fill={CHART_COLORS.critical} />
          <Bar dataKey="not_tested" name="Not tested" stackId="s" fill={CHART_COLORS.inconclusive} />
          {/* CHART_COLORS.low, not .brand/.medium - those two are byte-identical
              hex values, which would visually fuse this segment into "partial".
              No corner radius on this stack (dropped from the old top segment
              too): whichever segment ends up on top varies per domain now that
              there are 5 possible segments, and a zero-height review_required
              segment (the common case today) would otherwise leave the real
              top segment looking un-rounded. */}
          <Bar dataKey="review_required" name="Review required" stackId="s" fill={CHART_COLORS.low} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
