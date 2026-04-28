'use client';

import { useState, useEffect, useCallback } from 'react';
import SearchBar from '../../components/search/SearchBar';
import ThreatTable from '../../components/threats/ThreatTable';
import FacetedFilters from '../../components/threats/FacetedFilters';
import ThreatDetail from '../../components/threats/ThreatDetail';
import { atlasSearch, listURLs, updateURLStatus } from '../../lib/api';

export default function ThreatsPage() {
  const [urls, setUrls] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchLoading, setSearchLoading] = useState(false);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState({});
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [page, setPage] = useState(0);
  const limit = 20;

  const fetchURLs = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = { skip: page * limit, limit };
      if (filters.classification) params.classification = filters.classification;
      if (filters.status) params.status = filters.status;
      if (filters.domain) params.domain = filters.domain;
      const res = await listURLs(params);
      setUrls(res.data?.urls || []);
      setTotal(res.data?.total || 0);
    } catch (err) {
      console.error('Failed to fetch URLs:', err);
      setUrls([]);
      setTotal(0);
      setError(err?.response?.data?.detail || err?.message || 'Failed to load Threat Database data.');
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  useEffect(() => {
    fetchURLs();
  }, [fetchURLs]);

  const handleSearch = async (query) => {
    setSearchLoading(true);
    setError('');
    try {
      const res = await atlasSearch({
        query,
        filters: filters.classification ? { threatClassification: filters.classification } : undefined,
        limit: 30,
      });
      setUrls(res.data?.results || []);
      setTotal(res.data?.totalResults || 0);
    } catch (err) {
      console.error('Search failed:', err);
      setUrls([]);
      setTotal(0);
      setError(err?.response?.data?.detail || err?.message || 'Threat search failed.');
    } finally {
      setSearchLoading(false);
    }
  };

  const handleStatusChange = async (id, status) => {
    try {
      await updateURLStatus(id, status);
      setSelectedThreat(null);
      fetchURLs();
    } catch (err) {
      console.error('Status update failed:', err);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <SearchBar
        onSearch={handleSearch}
        loading={searchLoading}
        placeholder="Search URLs, domains, threat descriptions (Atlas Search)..."
      />

      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 20 }}>
        <FacetedFilters filters={filters} onChange={(f) => { setFilters(f); setPage(0); }} />

        <div>
          {error && (
            <div
              style={{
                marginBottom: 12,
                border: '1px solid #F9D3C8',
                background: '#FFF1ED',
                color: '#9C2B10',
                borderRadius: 8,
                padding: '10px 12px',
                fontSize: 13,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
              }}
            >
              <span>Threat Database failed to load: {error}</span>
              <button
                onClick={fetchURLs}
                style={{
                  border: '1px solid #E8A18D',
                  background: '#fff',
                  color: '#9C2B10',
                  borderRadius: 6,
                  padding: '6px 10px',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Retry
              </button>
            </div>
          )}

          {!loading && !error && total === 0 && (
            <div
              style={{
                marginBottom: 12,
                border: '1px solid #E8EDEB',
                background: '#F9FAFB',
                color: '#45525B',
                borderRadius: 8,
                padding: '10px 12px',
                fontSize: 13,
              }}
            >
              No rows matched the current search/filters.
            </div>
          )}

          <ThreatTable urls={urls} onRowClick={setSelectedThreat} />

          {/* Pagination */}
          {total > limit && (
            <div style={{ display: 'flex', justifyContent: 'center', gap: 12, marginTop: 16 }}>
              <button
                disabled={page === 0}
                onClick={() => setPage(p => p - 1)}
                style={{
                  padding: '8px 16px', borderRadius: 6,
                  border: '1px solid #E8EDEB', background: '#fff',
                  cursor: page === 0 ? 'not-allowed' : 'pointer',
                  fontSize: 13, color: '#5C6C75',
                }}
              >
                Previous
              </button>
              <span style={{ padding: '8px 0', fontSize: 13, color: '#5C6C75' }}>
                Page {page + 1} of {Math.ceil(total / limit)}
              </span>
              <button
                disabled={(page + 1) * limit >= total}
                onClick={() => setPage(p => p + 1)}
                style={{
                  padding: '8px 16px', borderRadius: 6,
                  border: '1px solid #E8EDEB', background: '#fff',
                  cursor: (page + 1) * limit >= total ? 'not-allowed' : 'pointer',
                  fontSize: 13, color: '#5C6C75',
                }}
              >
                Next
              </button>
            </div>
          )}
        </div>
      </div>

      <ThreatDetail
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
        onStatusChange={handleStatusChange}
      />
    </div>
  );
}
