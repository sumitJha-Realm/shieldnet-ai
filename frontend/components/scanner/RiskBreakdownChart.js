'use client';

import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid, Cell,
} from 'recharts';
import { useState } from 'react';

const FACTOR_COLORS = {
  domainAge: '#016BF8',
  ssl: '#00ED64',
  entropy: '#FFC010',
  dns: '#8B5CF6',
  hosting: '#5C6C75',
  vectorSimilarity: '#CF4A22',
  dgaScore: '#DB3030',
  structuralScore: '#F97316',
  homoglyphScore: '#944F01',
  brandImpersonation: '#E11D48',
  keywordBonus: '#7C3AED',
};

const FACTOR_ICONS = {
  domainAge: '📅',
  ssl: '🔒',
  entropy: '🎲',
  dns: '🌐',
  hosting: '🏗️',
  vectorSimilarity: '🔍',
  dgaScore: '⚙️',
  structuralScore: '🛡️',
  homoglyphScore: '👁️',
  brandImpersonation: '🏛️',
  keywordBonus: '🔑',
};

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div style={{
      background: '#1a1c1e', color: '#E8EDEB', padding: '10px 14px',
      borderRadius: 8, fontSize: 12, lineHeight: 1.6, maxWidth: 220,
    }}>
      <div style={{ fontWeight: 700, marginBottom: 4 }}>{FACTOR_ICONS[d.key] || '•'} {d.factor}</div>
      <div>Raw Signal: <strong>{(d.raw * 100).toFixed(0)}%</strong></div>
      <div>Weight: <strong>{(d.weight * 100).toFixed(0)}%</strong></div>
      <div>Contribution: <strong style={{ color: '#00ED64' }}>{d.contribution.toFixed(1)} pts</strong></div>
    </div>
  );
}

export default function RiskBreakdownChart({ breakdown, totalScore }) {
  const [view, setView] = useState('bar'); // 'bar' | 'radar'

  if (!breakdown || breakdown.length === 0) return null;

  const sorted = [...breakdown].sort((a, b) => b.contribution - a.contribution);
  const radarData = breakdown.map(f => ({
    ...f,
    rawPct: Math.round(f.raw * 100),
  }));

  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h3 style={{ fontSize: 16, fontWeight: 600, margin: 0, color: '#1a1c1e' }}>
            Risk Score Breakdown
          </h3>
          <p style={{ fontSize: 12, color: '#5C6C75', margin: '4px 0 0' }}>
            Weighted contribution of each detection factor to the total score of <strong>{totalScore}</strong>
          </p>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {['bar', 'radar'].map(v => (
            <button
              key={v}
              onClick={() => setView(v)}
              style={{
                padding: '4px 12px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                border: '1px solid #E8EDEB', cursor: 'pointer',
                background: view === v ? '#016BF8' : '#fff',
                color: view === v ? '#fff' : '#1a1c1e',
              }}
            >
              {v === 'bar' ? '📊 Bar' : '🕸️ Radar'}
            </button>
          ))}
        </div>
      </div>

      {view === 'bar' ? (
        <ResponsiveContainer width="100%" height={Math.max(280, sorted.length * 36)}>
          <BarChart data={sorted} layout="vertical" margin={{ left: 120, right: 20, top: 5, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#E8EDEB" horizontal={false} />
            <XAxis type="number" tick={{ fontSize: 11 }} domain={[0, 'auto']} unit=" pts" />
            <YAxis
              type="category" dataKey="factor" tick={{ fontSize: 11 }} width={110}
              tickFormatter={(v) => `${FACTOR_ICONS[sorted.find(f => f.factor === v)?.key] || ''} ${v}`}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="contribution" radius={[0, 4, 4, 0]} barSize={20}>
              {sorted.map((entry, i) => (
                <Cell key={i} fill={FACTOR_COLORS[entry.key] || '#016BF8'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <ResponsiveContainer width="100%" height={360}>
          <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
            <PolarGrid stroke="#E8EDEB" />
            <PolarAngleAxis dataKey="factor" tick={{ fontSize: 10, fill: '#3D4F58' }} />
            <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fontSize: 9 }} />
            <Tooltip content={<CustomTooltip />} />
            <Radar
              name="Raw Signal"
              dataKey="rawPct"
              stroke="#016BF8"
              fill="#016BF8"
              fillOpacity={0.25}
              strokeWidth={2}
            />
          </RadarChart>
        </ResponsiveContainer>
      )}

      {/* Factor summary pills */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 16 }}>
        {sorted.filter(f => f.contribution > 0).map(f => (
          <span key={f.key} style={{
            padding: '4px 10px', borderRadius: 16, fontSize: 11, fontWeight: 600,
            background: `${FACTOR_COLORS[f.key] || '#016BF8'}18`,
            color: FACTOR_COLORS[f.key] || '#016BF8',
            display: 'flex', alignItems: 'center', gap: 4,
          }}>
            {FACTOR_ICONS[f.key]} {f.factor}: {f.contribution.toFixed(1)}pts
          </span>
        ))}
      </div>
    </div>
  );
}
