'use client';

export default function ThreatDetail({ threat, onClose, onStatusChange }) {
  if (!threat) return null;

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.5)', display: 'flex',
      alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    }} onClick={onClose}>
      <div style={{
        background: '#fff', borderRadius: 16, padding: 32,
        maxWidth: 640, width: '90%', maxHeight: '80vh', overflowY: 'auto',
        boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <h2 style={{ fontSize: 20, fontWeight: 700 }}>Threat Analysis Detail</h2>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', fontSize: 24,
            cursor: 'pointer', color: '#5C6C75',
          }}>×</button>
        </div>

        {/* URL Info */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: '#5C6C75', fontWeight: 500 }}>URL</div>
          <div style={{ fontSize: 14, fontWeight: 600, wordBreak: 'break-all', marginTop: 4 }}>{threat.url}</div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 11, color: '#5C6C75', fontWeight: 500 }}>Domain</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginTop: 4 }}>{threat.domain}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: '#5C6C75', fontWeight: 500 }}>Risk Score</div>
            <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4, color: threat.riskScore >= 75 ? '#DB3030' : '#FFC010' }}>
              {threat.riskScore}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: '#5C6C75', fontWeight: 500 }}>Classification</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginTop: 4, textTransform: 'uppercase' }}>
              {threat.threatClassification}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: '#5C6C75', fontWeight: 500 }}>DNS Status</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginTop: 4 }}>{threat.dnsStatus}</div>
          </div>
        </div>

        {/* Status Note */}
        {threat.statusNote && (
          <div style={{
            padding: '12px 16px', borderRadius: 8, marginBottom: 20,
            background: threat.status === 'blocked' ? '#FFEAE5'
              : threat.status === 'allowed' ? '#E3FCF7' : '#FFF8E6',
            border: `1px solid ${threat.status === 'blocked' ? '#CF4A22'
              : threat.status === 'allowed' ? '#00684A' : '#944F01'}33`,
            fontSize: 13, fontWeight: 600,
            color: threat.status === 'blocked' ? '#CF4A22'
              : threat.status === 'allowed' ? '#00684A' : '#944F01',
          }}>
            ⚠ {threat.statusNote}
          </div>
        )}

        {/* Summary */}
        <div style={{
          padding: 16, borderRadius: 8, background: '#F5F6F7',
          marginBottom: 20, fontSize: 13, color: '#3D4F58', lineHeight: 1.5,
        }}>
          {threat.summaryText}
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={() => onStatusChange?.(threat._id, 'blocked')}
            style={{
              flex: 1, padding: '10px', borderRadius: 8,
              background: '#CF4A22', color: '#fff', border: 'none',
              fontWeight: 600, fontSize: 13, cursor: 'pointer',
            }}
          >
            Confirm Block
          </button>
          <button
            onClick={() => onStatusChange?.(threat._id, 'allowed')}
            style={{
              flex: 1, padding: '10px', borderRadius: 8,
              background: '#00684A', color: '#fff', border: 'none',
              fontWeight: 600, fontSize: 13, cursor: 'pointer',
            }}
          >
            Mark as Safe
          </button>
          <button
            onClick={onClose}
            style={{
              flex: 1, padding: '10px', borderRadius: 8,
              background: '#F5F6F7', color: '#5C6C75', border: '1px solid #E8EDEB',
              fontWeight: 600, fontSize: 13, cursor: 'pointer',
            }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
