'use client';

function Row({ label, value }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
      <span style={{ color: '#5C6C75' }}>{label}</span>
      <span style={{ color: '#1A1C1E', fontWeight: 600, textAlign: 'right' }}>{value}</span>
    </div>
  );
}

function Bullet({ children }) {
  return (
    <li style={{ marginBottom: 6, lineHeight: 1.45, color: '#3D4F58', fontSize: 12 }}>
      {children}
    </li>
  );
}

export default function SearchFeatureShowcase({ activeTab, result }) {
  const isAtlas = activeTab === 'atlas';
  const isVector = activeTab === 'vector';
  const isHybrid = activeTab === 'hybrid';
  const isUnified = activeTab === 'unified';

  const atlasMs = result?.atlas?.executionTimeMs ?? result?.executionTimeMs;
  const vectorMs = result?.vector?.executionTimeMs ?? result?.executionTimeMs;
  const hybridMs = result?.hybrid?.executionTimeMs ?? result?.executionTimeMs;
  const totalMs = result?.totalExecutionTimeMs ?? result?.executionTimeMs;

  return (
    <div
      style={{
        background: '#fff',
        borderRadius: 12,
        padding: 18,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        border: '1px solid #E8EDEB',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h4 style={{ fontSize: 14, fontWeight: 700, color: '#1A1C1E' }}>
          Demo: Features Used In This Search
        </h4>
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: 0.3,
            color: '#016BF8',
            background: '#EAF2FF',
            borderRadius: 999,
            padding: '4px 10px',
          }}
        >
          {activeTab}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        {(isAtlas || isHybrid || isUnified) && (
          <div style={{ border: '1px solid #E8EDEB', borderRadius: 10, padding: 12, background: '#FBFDFF' }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#1A1C1E', marginBottom: 8 }}>
              Atlas Search (Lexical)
            </div>
            <ul style={{ margin: '0 0 8px 16px', padding: 0 }}>
              <Bullet>Full-text query on url, domain, summaryText</Bullet>
              <Bullet>Fuzzy match enabled (maxEdits=2, prefixLength=2)</Bullet>
              <Bullet>Highlight extraction for matched text fields</Bullet>
              <Bullet>Supports structured filters (status, classification, risk range, doc type)</Bullet>
            </ul>
            <Row label="Index" value="url_search_index" />
            <Row label="Execution" value={`${atlasMs != null ? atlasMs.toFixed(0) : '-'} ms`} />
          </div>
        )}

        {(isVector || isHybrid || isUnified) && (
          <div style={{ border: '1px solid #E8EDEB', borderRadius: 10, padding: 12, background: '#FAFFFC' }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#1A1C1E', marginBottom: 8 }}>
              Vector Search (Semantic)
            </div>
            <ul style={{ margin: '0 0 8px 16px', padding: 0 }}>
              <Bullet>Query embedding generation via Voyage model</Bullet>
              <Bullet>ANN vector similarity search (cosine) on embedding field</Bullet>
              <Bullet>numCandidates=100, then top-k ranking by similarity</Bullet>
              <Bullet>Optional metadata filtering (threatClassification, status)</Bullet>
            </ul>
            <Row label="Index" value="url_vector_index" />
            <Row label="Execution" value={`${vectorMs != null ? vectorMs.toFixed(0) : '-'} ms`} />
          </div>
        )}
      </div>

      {(isHybrid || isUnified) && (
        <div
          style={{
            marginTop: 12,
            border: '1px dashed #CAD7E5',
            borderRadius: 10,
            padding: 10,
            background: '#F8FBFF',
            fontSize: 12,
            color: '#3D4F58',
          }}
        >
          Hybrid uses MongoDB rank fusion to combine Atlas and Vector rankings.
          {(result?.hybrid?.atlasWeight != null || result?.atlasWeight != null) && (
            <span style={{ marginLeft: 6, fontWeight: 600, color: '#1A1C1E' }}>
              Weights: Atlas {(result?.hybrid?.atlasWeight ?? result?.atlasWeight ?? 0.4)} / Vector {(result?.hybrid?.vectorWeight ?? result?.vectorWeight ?? 0.6)}
            </span>
          )}
          <span style={{ marginLeft: 6 }}>
            Total execution: {totalMs != null ? totalMs.toFixed(0) : '-'} ms.
          </span>
        </div>
      )}
    </div>
  );
}
