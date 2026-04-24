'use client';

import SearchResults from './VectorSearchResults';

export default function HybridResults({ data }) {
  if (!data) return null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {data.atlas && <SearchResults data={data.atlas} searchType="atlas" />}
      {data.vector && <SearchResults data={data.vector} searchType="vector" />}
      {data.hybrid && <SearchResults data={data.hybrid} searchType="hybrid" />}
      <div style={{
        padding: '8px 16px', borderRadius: 8,
        background: '#F5F6F7', fontSize: 12, color: '#5C6C75',
        textAlign: 'center',
      }}>
        Total execution: {data.totalExecutionTimeMs?.toFixed(0)}ms
      </div>
    </div>
  );
}
