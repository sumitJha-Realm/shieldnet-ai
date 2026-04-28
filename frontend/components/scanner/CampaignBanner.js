'use client';

/* ── CampaignBanner — shown on scan results when a campaign is detected ── */

const SEVERITY_COLORS = {
  critical: { bg: '#FFEAE5', border: '#CF4A22', color: '#CF4A22', icon: '🔴' },
  high:     { bg: '#FFF1EB', border: '#E06C00', color: '#E06C00', icon: '🟠' },
  medium:   { bg: '#FFF8E6', border: '#944F01', color: '#944F01', icon: '🟡' },
  low:      { bg: '#E3FCF7', border: '#00684A', color: '#00684A', icon: '🟢' },
};

export default function CampaignBanner({ campaign }) {
  if (!campaign) return null;

  const sev = SEVERITY_COLORS[campaign.severity] || SEVERITY_COLORS.medium;
  const domainList = (campaign.domains || []).slice(0, 6);
  const tldList = (campaign.sharedTlds || []).slice(0, 5);

  return (
    <div style={{
      background: sev.bg,
      border: `2px solid ${sev.border}`,
      borderRadius: 12,
      padding: 20,
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <span style={{ fontSize: 22 }}>🎯</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: sev.color }}>
            CAMPAIGN DETECTED
          </div>
          <div style={{ fontSize: 13, color: '#3D4F58', marginTop: 2 }}>
            {campaign.name}
          </div>
        </div>
        <span style={{
          padding: '4px 12px', borderRadius: 20,
          background: sev.border, color: '#fff',
          fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
        }}>
          {campaign.severity}
        </span>
        <span style={{
          padding: '4px 12px', borderRadius: 20,
          background: '#1a1c1e', color: '#fff',
          fontSize: 11, fontWeight: 700,
        }}>
          {campaign.status}
        </span>
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 14 }}>
        {[
          { label: 'URLs in campaign', value: campaign.urlCount },
          { label: 'Avg risk score', value: campaign.avgRiskScore?.toFixed(1) },
          { label: 'Avg similarity', value: `${(campaign.avgSimilarity * 100).toFixed(0)}%` },
          { label: 'Attack type', value: (campaign.attackCategory || '').replace(/_/g, ' ') },
          { label: 'Cluster size', value: campaign.clusterSize },
        ].map(s => (
          <div key={s.label} style={{
            padding: '6px 14px', borderRadius: 8,
            background: '#fff', border: '1px solid #E8EDEB',
            fontSize: 12,
          }}>
            <span style={{ color: '#5C6C75' }}>{s.label}: </span>
            <span style={{ fontWeight: 700, color: '#1a1c1e' }}>{s.value}</span>
          </div>
        ))}
      </div>

      {/* Domains + TLDs */}
      <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
        {domainList.length > 0 && (
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: '#5C6C75', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Linked Domains
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {domainList.map(d => (
                <span key={d} style={{
                  padding: '3px 10px', borderRadius: 12,
                  background: '#fff', border: '1px solid #E8EDEB',
                  fontSize: 11, color: '#3D4F58', fontFamily: 'monospace',
                }}>
                  {d}
                </span>
              ))}
              {(campaign.domains || []).length > 6 && (
                <span style={{ fontSize: 11, color: '#5C6C75', padding: '3px 6px' }}>
                  +{campaign.domains.length - 6} more
                </span>
              )}
            </div>
          </div>
        )}
        {tldList.length > 0 && (
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: '#5C6C75', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Shared TLDs
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {tldList.map(t => (
                <span key={t} style={{
                  padding: '3px 10px', borderRadius: 12,
                  background: sev.bg, border: `1px solid ${sev.border}44`,
                  fontSize: 11, fontWeight: 600, color: sev.color,
                }}>
                  .{t}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Timestamps */}
      <div style={{ display: 'flex', gap: 16, marginTop: 12, fontSize: 11, color: '#889397' }}>
        <span>First seen: {new Date(campaign.firstSeen).toLocaleString()}</span>
        <span>Last seen: {new Date(campaign.lastSeen).toLocaleString()}</span>
      </div>
    </div>
  );
}
