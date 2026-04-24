'use client';

export default function SearchResults({ data, searchType }) {
  if (!data) return null;

  const results = data.results || [];
  const typeLabel = {
    atlas: 'Atlas Search (Text)',
    vector: 'Vector Search (Semantic)',
    hybrid: 'Hybrid Search (Rank Fusion)',
  }[searchType] || searchType;

  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 20,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h4 style={{ fontSize: 14, fontWeight: 600, color: '#1a1c1e' }}>{typeLabel}</h4>
        <div style={{ display: 'flex', gap: 12, fontSize: 11, color: '#5C6C75' }}>
          <span>{data.totalResults || results.length} results</span>
          <span>{data.executionTimeMs?.toFixed(0)}ms</span>
        </div>
      </div>
      {results.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 24, color: '#5C6C75', fontSize: 13 }}>
          No results found
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {results.map((r, i) => (
            <div key={r._id || i} style={{
              padding: '10px 14px', borderRadius: 8,
              background: '#F5F6F7', border: '1px solid #E8EDEB',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.url}
                  </div>
                  <div style={{ fontSize: 11, color: '#5C6C75', marginTop: 2 }}>
                    {r.domain} · {r.threatClassification} · Risk: {r.riskScore}
                  </div>
                </div>
                <div style={{
                  padding: '2px 10px', borderRadius: 12,
                  background: '#E3FCF7', color: '#016BF8',
                  fontSize: 11, fontWeight: 700, whiteSpace: 'nowrap', marginLeft: 8,
                }}>
                  {typeof r.score === 'number' ? r.score.toFixed(4) : '—'}
                </div>
              </div>
              {/* Score details for hybrid */}
              {r.scoreDetails && (
                <div style={{ marginTop: 6, fontSize: 11, color: '#5C6C75', display: 'flex', gap: 12 }}>
                  {r.scoreDetails.atlasScore != null && <span>Atlas: {r.scoreDetails.atlasScore.toFixed(4)}</span>}
                  {r.scoreDetails.vectorScore != null && <span>Vector: {r.scoreDetails.vectorScore.toFixed(4)}</span>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
