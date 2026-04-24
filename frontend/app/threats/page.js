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
  const [filters, setFilters] = useState({});
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [page, setPage] = useState(0);
  const limit = 20;

  const fetchURLs = useCallback(async () => {
    setLoading(true);
    try {
      const params = { skip: page * limit, limit };
      if (filters.classification) params.classification = filters.classification;
      if (filters.status) params.status = filters.status;
      const res = await listURLs(params);
      setUrls(res.data?.urls || []);
      setTotal(res.data?.total || 0);
    } catch (err) {
      console.error('Failed to fetch URLs:', err);
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  useEffect(() => {
    fetchURLs();
  }, [fetchURLs]);

  const handleSearch = async (query) => {
    setSearchLoading(true);
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
