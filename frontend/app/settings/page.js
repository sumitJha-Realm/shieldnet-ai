'use client';

import { useState, useEffect } from 'react';
import { getSearchInfo, testAtlasIndex, testVectorIndex } from '../../lib/api';

export default function SettingsPage() {
  const [info, setInfo] = useState(null);
  const [atlasTest, setAtlasTest] = useState(null);
  const [vectorTest, setVectorTest] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSearchInfo()
      .then(res => setInfo(res.data))
      .catch(() => setInfo({ error: 'Failed to load' }))
      .finally(() => setLoading(false));
  }, []);

  const handleTestAtlas = async () => {
    setAtlasTest(null);
    try {
      const res = await testAtlasIndex();
      setAtlasTest(res.data);
    } catch (err) {
      setAtlasTest({ status: 'error', error: err.message });
    }
  };

  const handleTestVector = async () => {
    setVectorTest(null);
    try {
      const res = await testVectorIndex();
      setVectorTest(res.data);
    } catch (err) {
      setVectorTest({ status: 'error', error: err.message });
    }
  };

  const cardStyle = {
    background: '#fff', borderRadius: 12, padding: 24,
    boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
  };

  const btnStyle = {
    padding: '8px 20px', borderRadius: 6,
    border: '1px solid #E8EDEB', background: '#016BF8',
    color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 800 }}>
      {/* System Status */}
      <div style={cardStyle}>
        <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>System Status</h3>
        {loading ? (
          <div style={{ color: '#5C6C75' }}>Loading...</div>
        ) : info?.error ? (
          <div style={{ color: '#CF4A22' }}>Backend not reachable. Ensure it is running on port 8000.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #F5F6F7' }}>
              <span style={{ color: '#5C6C75' }}>Database</span>
              <span style={{ fontWeight: 600 }}>{info?.database || '—'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #F5F6F7' }}>
              <span style={{ color: '#5C6C75' }}>Total Documents</span>
              <span style={{ fontWeight: 600 }}>{info?.urlsCollection?.totalDocuments?.toLocaleString() || '0'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #F5F6F7' }}>
              <span style={{ color: '#5C6C75' }}>With Embeddings</span>
              <span style={{ fontWeight: 600 }}>{info?.urlsCollection?.documentsWithEmbedding?.toLocaleString() || '0'}</span>
            </div>
            {info?.services && Object.entries(info.services).map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #F5F6F7' }}>
                <span style={{ color: '#5C6C75' }}>{k}</span>
                <span style={{ fontWeight: 600, color: v === 'initialized' ? '#00684A' : '#CF4A22' }}>{v}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Index Tests */}
      <div style={cardStyle}>
        <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Search Index Tests</h3>
        <div style={{ display: 'flex', gap: 16 }}>
          <div style={{ flex: 1 }}>
            <button onClick={handleTestAtlas} style={btnStyle}>Test Atlas Search Index</button>
            {atlasTest && (
              <div style={{
                marginTop: 12, padding: 12, borderRadius: 8,
                background: atlasTest.reachable ? '#E3FCF7' : '#FFEAE5',
                color: atlasTest.reachable ? '#00684A' : '#CF4A22',
                fontSize: 12,
              }}>
                {atlasTest.reachable
                  ? `✓ Atlas Search index "${atlasTest.indexName}" is reachable`
                  : `✗ Atlas Search index unreachable: ${atlasTest.error || 'unknown error'}`}
              </div>
            )}
          </div>
          <div style={{ flex: 1 }}>
            <button onClick={handleTestVector} style={btnStyle}>Test Vector Search Index</button>
            {vectorTest && (
              <div style={{
                marginTop: 12, padding: 12, borderRadius: 8,
                background: vectorTest.reachable ? '#E3FCF7' : '#FFEAE5',
                color: vectorTest.reachable ? '#00684A' : '#CF4A22',
                fontSize: 12,
              }}>
                {vectorTest.reachable
                  ? `✓ Vector Search index "${vectorTest.indexName}" is reachable`
                  : `✗ Vector Search index unreachable: ${vectorTest.error || 'unknown error'}`}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Environment Info */}
      <div style={cardStyle}>
        <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Configuration</h3>
        <div style={{
          padding: 16, borderRadius: 8, background: '#1a1c1e',
          color: '#00ED64', fontFamily: 'monospace', fontSize: 12,
          lineHeight: 1.8, overflowX: 'auto',
        }}>
          <div>MONGODB_URI=mongodb+srv://***@cluster.mongodb.net/</div>
          <div>DB_NAME=shieldnet-ai</div>
          <div>VOYAGE_AI_API_KEY=***</div>
          <div>ATLAS_SEARCH_INDEX=url_search_index</div>
          <div>VECTOR_SEARCH_INDEX=url_vector_index</div>
          <div>FRONTEND_URL=http://localhost:3000</div>
        </div>
        <p style={{ fontSize: 12, color: '#5C6C75', marginTop: 12 }}>
          Configure these variables in your <code>.env</code> file in the project root.
        </p>
      </div>
    </div>
  );
}
