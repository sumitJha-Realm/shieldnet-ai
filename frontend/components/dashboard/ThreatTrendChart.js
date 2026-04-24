'use client';

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const COLORS = {
  phishing: '#CF4A22',
  malware: '#DB3030',
  c2: '#8B5CF6',
  suspicious: '#FFC010',
  benign: '#00ED64',
};

export default function ThreatTrendChart({ data }) {
  // Transform aggregated trend data into chart format
  const chartData = {};
  (data || []).forEach(item => {
    const date = item._id?.date || 'unknown';
    const cls = item._id?.classification || 'unknown';
    if (!chartData[date]) chartData[date] = { date };
    chartData[date][cls] = item.count;
  });

  const formatted = Object.values(chartData).sort((a, b) => a.date.localeCompare(b.date));

  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
        Threat Trends (Last 30 Days)
      </h3>
      {formatted.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 40, color: '#5C6C75' }}>
          No trend data available. Seed the database to populate.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={formatted}>
            <CartesianGrid strokeDasharray="3 3" stroke="#E8EDEB" />
            <XAxis dataKey="date" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip />
            <Legend />
            {Object.entries(COLORS).map(([key, color]) => (
              <Area
                key={key}
                type="monotone"
                dataKey={key}
                stackId="1"
                stroke={color}
                fill={color}
                fillOpacity={0.6}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
