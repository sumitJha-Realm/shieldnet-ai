'use client';

const LEVEL_CONFIG = {
  critical: { color: '#DB3030', bg: '#FFEAE5', label: 'CRITICAL' },
  high: { color: '#CF4A22', bg: '#FFF1EB', label: 'HIGH' },
  medium: { color: '#FFC010', bg: '#FFF8E6', label: 'MEDIUM' },
  low: { color: '#00ED64', bg: '#E6FFF0', label: 'LOW' },
};

export default function RiskGauge({ score, level }) {
  const cfg = LEVEL_CONFIG[level] || LEVEL_CONFIG.medium;
  const rotation = (score / 100) * 180 - 90; // -90 to 90 degrees

  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      textAlign: 'center',
    }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
        Risk Score
      </h3>
      {/* Gauge */}
      <div style={{ position: 'relative', width: 200, height: 120, margin: '0 auto' }}>
        <svg viewBox="0 0 200 120" width="200" height="120">
          {/* Background arc */}
          <path d="M 20 110 A 80 80 0 0 1 180 110" fill="none" stroke="#E8EDEB" strokeWidth="12" strokeLinecap="round" />
          {/* Score arc */}
          <path
            d="M 20 110 A 80 80 0 0 1 180 110"
            fill="none" stroke={cfg.color} strokeWidth="12" strokeLinecap="round"
            strokeDasharray={`${(score / 100) * 251.2} 251.2`}
          />
        </svg>
        <div style={{
          position: 'absolute', bottom: 0, left: '50%',
          transform: 'translateX(-50%)',
          fontSize: 36, fontWeight: 700, color: cfg.color,
        }}>
          {score}
        </div>
      </div>
      <div style={{
        display: 'inline-block', marginTop: 12,
        padding: '4px 16px', borderRadius: 20,
        background: cfg.bg, color: cfg.color,
        fontWeight: 700, fontSize: 13,
      }}>
        {cfg.label}
      </div>
    </div>
  );
}
