'use client';

import { useState, useEffect } from 'react';
import { getDashboardStats, getDashboardTrends, getThreatLogs } from '../../lib/api';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, LineChart, Line,
} from 'recharts';

const COLORS = ['#CF4A22', '#DB3030', '#8B5CF6', '#FFC010', '#00ED64', '#016BF8'];

export default function AnalyticsPage() {
  const [stats, setStats] = useState(null);
  const [trends, setTrends] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      getDashboardStats().catch(() => ({ data: {} })),
      getDashboardTrends(60).catch(() => ({ data: [] })),
      getThreatLogs({ limit: 200 }).catch(() => ({ data: { logs: [] } })),
    ]).then(([statsRes, trendsRes, logsRes]) => {
      setStats(statsRes.data);
      setTrends(trendsRes.data);
      setLogs(logsRes.data?.logs || []);
      setLoading(false);
    });
  }, []);

  // Aggregate department stats from logs
  const deptCounts = {};
  logs.forEach(l => {
    const dept = l.userDepartment || 'Unknown';
    deptCounts[dept] = (deptCounts[dept] || 0) + 1;
  });
  const deptData = Object.entries(deptCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, count]) => ({ name: name.replace('Ministry of ', ''), count }));

  // Risk distribution pie
  const riskPieData = stats?.riskDistribution
    ? Object.entries(stats.riskDistribution).map(([name, value]) => ({ name, value }))
    : [];

  // Trend data for line chart
  const trendMap = {};
  (trends || []).forEach(item => {
    const date = item._id?.date || 'unknown';
    if (!trendMap[date]) trendMap[date] = { date, total: 0 };
    trendMap[date].total += item.count;
  });
  const lineData = Object.values(trendMap).sort((a, b) => a.date.localeCompare(b.date));

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', color: '#5C6C75' }}>
        Loading analytics...
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Threat Classification Distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        <div style={{
          background: '#fff', borderRadius: 12, padding: 24,
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Threat Classification Distribution</h3>
          {riskPieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={riskPieData}
                  cx="50%" cy="50%"
                  outerRadius={100}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {riskPieData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: '#5C6C75' }}>No data</div>
          )}
        </div>

        {/* Department Activity */}
        <div style={{
          background: '#fff', borderRadius: 12, padding: 24,
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Top Departments by Activity</h3>
          {deptData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={deptData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#E8EDEB" />
                <XAxis type="number" tick={{ fontSize: 11 }} />
                <YAxis type="category" dataKey="name" width={120} tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="count" fill="#016BF8" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: '#5C6C75' }}>No data</div>
          )}
        </div>
      </div>

      {/* Threat Volume Over Time */}
      <div style={{
        background: '#fff', borderRadius: 12, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Threat Volume Over Time</h3>
        {lineData.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={lineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E8EDEB" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Line type="monotone" dataKey="total" stroke="#016BF8" strokeWidth={2} dot={{ fill: '#016BF8', r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ textAlign: 'center', padding: 40, color: '#5C6C75' }}>No data</div>
        )}
      </div>

      {/* Summary Stats */}
      <div style={{
        background: '#fff', borderRadius: 12, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 24,
      }}>
        {[
          { label: 'Total URLs Analyzed', value: stats?.totalScanned || 0 },
          { label: 'Blocked Today', value: stats?.blockedToday || 0 },
          { label: 'Under Review', value: stats?.underReview || 0 },
          { label: 'Active Threats', value: stats?.activeThreats || 0 },
        ].map((item, i) => (
          <div key={i} style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#016BF8' }}>{item.value.toLocaleString()}</div>
            <div style={{ fontSize: 12, color: '#5C6C75', marginTop: 4 }}>{item.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
