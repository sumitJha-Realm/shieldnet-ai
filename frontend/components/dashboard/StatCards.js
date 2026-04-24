'use client';

const CARD_CONFIGS = [
  { key: 'totalScanned', label: 'Total URLs Scanned', color: '#016BF8', icon: '🔗' },
  { key: 'blockedToday', label: 'Blocked Today', color: '#CF4A22', icon: '🚫' },
  { key: 'underReview', label: 'Under Review', color: '#FFC010', icon: '🔎' },
  { key: 'activeThreats', label: 'Active Threats', color: '#DB3030', icon: '⚠️' },
];

export default function StatCards({ stats }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
      {CARD_CONFIGS.map(cfg => (
        <div key={cfg.key} style={{
          background: '#fff',
          borderRadius: 12,
          padding: '20px 24px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
          borderLeft: `4px solid ${cfg.color}`,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 13, color: '#5C6C75', fontWeight: 500 }}>{cfg.label}</span>
            <span style={{ fontSize: 24 }}>{cfg.icon}</span>
          </div>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#1a1c1e', marginTop: 8 }}>
            {stats?.[cfg.key]?.toLocaleString() ?? '—'}
          </div>
        </div>
      ))}
    </div>
  );
}
