'use client';

import { useState, useEffect, useCallback } from 'react';
import StatCards from '../components/dashboard/StatCards';
import ThreatTrendChart from '../components/dashboard/ThreatTrendChart';
import RecentActivity from '../components/dashboard/RecentActivity';
import { getDashboardStats, getDashboardTrends, getThreatLogs } from '../lib/api';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const PIE_COLORS = {
  phishing: '#CF4A22',
  malware: '#DB3030',
  c2: '#8B5CF6',
  suspicious: '#FFC010',
  benign: '#00ED64',
};

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [trends, setTrends] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, trendsRes, logsRes] = await Promise.all([
        getDashboardStats().catch(() => ({ data: {} })),
        getDashboardTrends().catch(() => ({ data: [] })),
        getThreatLogs({ limit: 20 }).catch(() => ({ data: { logs: [] } })),
      ]);
      setStats(statsRes.data);
      setTrends(trendsRes.data);
      setLogs(logsRes.data?.logs || []);
      setError(null);
    } catch (err) {
      setError('Failed to load dashboard data. Ensure the backend is running.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const riskPieData = stats?.riskDistribution
    ? Object.entries(stats.riskDistribution).map(([name, value]) => ({ name, value }))
    : [];

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', color: '#5C6C75' }}>
        Loading dashboard...
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {error && (
        <div style={{
          padding: '12px 20px', borderRadius: 8,
          background: '#FFF3CD', color: '#856404', fontSize: 13,
          border: '1px solid #FFEEBA',
        }}>
          {error}
        </div>
      )}

      <StatCards stats={stats} />

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24 }}>
        <ThreatTrendChart data={trends} />

        {/* Risk Distribution Pie */}
        <div style={{
          background: '#fff', borderRadius: 12, padding: 24,
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
            Risk Distribution
          </h3>
          {riskPieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={riskPieData}
                  cx="50%" cy="50%"
                  outerRadius={80}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={false}
                >
                  {riskPieData.map((entry) => (
                    <Cell key={entry.name} fill={PIE_COLORS[entry.name] || '#5C6C75'} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: '#5C6C75' }}>No data</div>
          )}
        </div>
      </div>

      <RecentActivity logs={logs} />
    </div>
  );
}
