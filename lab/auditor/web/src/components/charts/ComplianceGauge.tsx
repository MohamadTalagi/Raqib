import { RadialBar, RadialBarChart, PolarAngleAxis } from "recharts";
import { CHART_COLORS } from "@/lib/colors";

function scoreColor(score: number): string {
  if (score >= 75) return CHART_COLORS.pass;
  if (score >= 50) return CHART_COLORS.medium;
  return CHART_COLORS.critical;
}

export function ComplianceGauge({ score }: { score: number }) {
  const color = scoreColor(score);
  const data = [{ name: "score", value: score, fill: color }];

  return (
    <div className="relative flex h-40 w-40 items-center justify-center">
      <RadialBarChart
        width={160}
        height={160}
        cx="50%"
        cy="50%"
        innerRadius={58}
        outerRadius={74}
        barSize={12}
        data={data}
        startAngle={90}
        endAngle={-270}
      >
        <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
        <RadialBar background={{ fill: CHART_COLORS.surfaceRaised }} dataKey="value" cornerRadius={6} />
      </RadialBarChart>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono-tabular text-3xl font-bold text-[var(--color-text)]">{score}</span>
        <span className="text-[10px] tracking-wide text-[var(--color-text-muted)] uppercase">/ 100</span>
      </div>
    </div>
  );
}
