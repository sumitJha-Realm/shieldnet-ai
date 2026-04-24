'use client';

export default function SimilarThreats({ threats }) {
  if (!threats || threats.length === 0) {
    return (
      <div style={{
        background: '#fff', borderRadius: 12, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, color: '#1a1c1e' }}>
          Similar Known Threats (Vector Search)
        </h3>
        <div style={{ textAlign: 'center', padding: 24, color: '#5C6C75' }}>
          No similar threats found or embeddings not available.
        </div>
      </div>
    );
  }

  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
        Similar Known Threats (Vector Search)
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {threats.map((t, i) => (
          <div key={t._id || i} style={{
            padding: '12px 16px', borderRadius: 8,
            background: '#F5F6F7', border: '1px solid #E8EDEB',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1c1e', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {t.url}
              </div>
              <div style={{ fontSize: 11, color: '#5C6C75', marginTop: 2 }}>
                {t.threatClassification} · {t.domain} · Risk: {t.riskScore}
              </div>
            </div>
            <div style={{
              padding: '4px 12px', borderRadius: 20,
              background: '#E3FCF7', color: '#016BF8',
              fontSize: 12, fontWeight: 700, whiteSpace: 'nowrap',
            }}>
              {((t.score || 0) * 100).toFixed(1)}% match
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
