import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipProps,
} from "recharts";
import type { ValueType, NameType } from "recharts/types/component/DefaultTooltipContent";
import type { ThreatData } from "../lib/threats";
import {
  getAttackTypeCounts,
  getThreatDistribution,
} from "../lib/threats";
import { DashboardPanel } from "./DashboardPanel";

interface ThreatChartsProps {
  data: ThreatData[];
}

function ThreatChartTooltip({
  active,
  payload,
}: TooltipProps<ValueType, NameType>) {
  if (!active || !payload?.length) {
    return null;
  }

  const item = payload[0];
  const label = typeof item.name === "string" ? item.name : "";
  const value = item.value;
  const suffix = item.dataKey === "count" ? "attacks" : "threats";
  const color = typeof item.payload?.color === "string" ? item.payload.color : item.fill;

  return (
    <div
      className="rounded-lg border px-4 py-2"
      style={{
        backgroundColor: "#0f1420",
        borderColor: "#1e2738",
        color: "#e8edf4",
      }}
    >
      <p className="font-medium">{label}</p>
      <p style={{ color }}>{value} {suffix}</p>
    </div>
  );
}

export function ThreatCharts({ data }: ThreatChartsProps) {
  const threatDistribution = getThreatDistribution(data);
  const attackTypes = getAttackTypeCounts(data);

  return (
    <div className="grid grid-cols-2 gap-6">
      {/* Pie Chart - Threat Distribution */}
      <DashboardPanel className="p-6">
        <h3 className="text-lg mb-6" style={{ color: "#e8edf4" }}>
          Threat Distribution
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={threatDistribution}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={100}
              paddingAngle={2}
              dataKey="value"
            >
              {threatDistribution.map((entry, index) => (
                <Cell key={`pie-cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<ThreatChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="grid grid-cols-2 gap-4 mt-6">
          {threatDistribution.map((item) => (
            <div key={`legend-${item.name}`} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-sm" style={{ color: "#8b92a8" }}>
                {item.name}
              </span>
              <span className="text-sm ml-auto" style={{ color: item.color }}>
                {item.value}
              </span>
            </div>
          ))}
        </div>
      </DashboardPanel>

      {/* Bar Chart - Attack Types */}
      <DashboardPanel className="p-6">
        <h3 className="text-lg mb-6" style={{ color: "#e8edf4" }}>
          Attacks by Type
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={attackTypes}>
            <XAxis
              dataKey="name"
              tick={{ fill: "#8b92a8", fontSize: 12 }}
              angle={-45}
              textAnchor="end"
              height={80}
            />
            <YAxis tick={{ fill: "#8b92a8", fontSize: 12 }} />
            <Tooltip content={<ThreatChartTooltip />} />
            <Bar dataKey="count" radius={[8, 8, 0, 0]}>
              {attackTypes.map((entry, index) => (
                <Cell key={`bar-cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </DashboardPanel>
    </div>
  );
}
