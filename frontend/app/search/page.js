'use client';

import { useState, useEffect } from 'react';
import SearchBar from '../../components/search/SearchBar';
import SearchResults from '../../components/search/VectorSearchResults';
import HybridResults from '../../components/search/HybridResults';
import SearchFeatureShowcase from '../../components/search/SearchFeatureShowcase';
import { atlasSearch, vectorSearch, hybridSearch, unifiedSearch, getDemoScenarios } from '../../lib/api';

const TABS = [
  { key: 'atlas', label: 'Atlas Search' },
  { key: 'vector', label: 'Vector Search' },
  { key: 'hybrid', label: 'Hybrid Search' },
  { key: 'unified', label: 'Unified (All)' },
];

export default function SearchPlaygroundPage() {
  const [activeTab, setActiveTab] = useState('atlas');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [scenarios, setScenarios] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    getDemoScenarios()
      .then(res => setScenarios(res.data || []))
      .catch(() => {});
  }, []);

  const handleSearch = async (query) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      let res;
      switch (activeTab) {
        case 'atlas':
          res = await atlasSearch({ query, limit: 15 });
          break;
        case 'vector':
          res = await vectorSearch({ query, limit: 10 });
          break;
        case 'hybrid':
          res = await hybridSearch({ query, atlasWeight: 0.4, vectorWeight: 0.6, limit: 15 });
          break;
        case 'unified':
          res = await unifiedSearch({ query, limit: 10 });
          break;
      }
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Search failed. Ensure backend is running and indexes exist.');
    } finally {
      setLoading(false);
    }
  };

  const runScenario = (scenario) => {
    const tab = scenario.searchType;
    if (TABS.find(t => t.key === tab)) setActiveTab(tab);
    handleSearch(scenario.query);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, background: '#fff', borderRadius: 10, padding: 4, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
        {TABS.map(tab => (
          <button
            key={tab.key}
            onClick={() => { setActiveTab(tab.key); setResult(null); }}
            style={{
              flex: 1, padding: '10px 0', borderRadius: 8,
              border: 'none', fontSize: 13, fontWeight: 600,
              cursor: 'pointer',
              background: activeTab === tab.key ? '#016BF8' : 'transparent',
              color: activeTab === tab.key ? '#fff' : '#5C6C75',
              transition: 'all 0.15s',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <SearchBar onSearch={handleSearch} loading={loading} placeholder={`Search with ${TABS.find(t => t.key === activeTab)?.label}...`} />

      <SearchFeatureShowcase activeTab={activeTab} result={result} />

      {error && (
        <div style={{
          padding: '12px 20px', borderRadius: 8,
          background: '#FFEAE5', color: '#CF4A22', fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {/* Demo Scenarios */}
      {!result && scenarios.length > 0 && (
        <div style={{
          background: '#fff', borderRadius: 12, padding: 20,
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        }}>
          <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: '#1a1c1e' }}>
            Demo Scenarios
          </h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
            {scenarios.map(s => (
              <div
                key={s.id}
                onClick={() => runScenario(s)}
                style={{
                  padding: '12px 16px', borderRadius: 8,
                  background: '#F5F6F7', border: '1px solid #E8EDEB',
                  cursor: 'pointer', transition: 'background 0.15s',
                }}
                onMouseEnter={e => e.currentTarget.style.background = '#EDF2F7'}
                onMouseLeave={e => e.currentTarget.style.background = '#F5F6F7'}
              >
                <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1c1e' }}>{s.name}</div>
                <div style={{ fontSize: 11, color: '#5C6C75', marginTop: 4 }}>{s.description}</div>
                <div style={{
                  marginTop: 6, fontSize: 10, fontWeight: 600,
                  color: '#016BF8', textTransform: 'uppercase',
                }}>
                  {s.searchType} search · &quot;{s.query}&quot;
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {result && activeTab === 'unified' ? (
        <HybridResults data={result} />
      ) : result ? (
        <SearchResults data={result} searchType={activeTab} />
      ) : null}
    </div>
  );
}
