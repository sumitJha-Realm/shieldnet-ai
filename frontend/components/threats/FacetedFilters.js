'use client';

import { useState, useEffect } from 'react';
import { getWatchedDomains } from '../../lib/api';

export default function FacetedFilters({ filters, onChange }) {
  const [watchedDomains, setWatchedDomains] = useState([]);

  useEffect(() => {
    getWatchedDomains()
      .then(res => setWatchedDomains(res.data?.domains || []))
      .catch(() => {});
  }, []);

  const handleChange = (key, value) => {
    onChange({ ...filters, [key]: value || undefined });
  };

  const selectStyle = {
    width: '100%', padding: '8px 12px', borderRadius: 6,
    border: '1px solid #E8EDEB', fontSize: 13, background: '#fff',
    outline: 'none',
  };

  const threatColor = (d) => {
    if (d.maxRiskScore >= 75) return '#D93025';
    if (d.maxRiskScore >= 50) return '#F4912A';
    return '#2E7D32';
  };

  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 20,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
        Filters
      </h4>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

        {/* Domain shortlist */}
        <div>
          <label style={{ fontSize: 11, fontWeight: 500, color: '#5C6C75', display: 'block', marginBottom: 4 }}>
            Base Domain
          </label>
          <select
            value={filters?.domain || ''}
            onChange={e => handleChange('domain', e.target.value)}
            style={selectStyle}
          >
            <option value="">All Domains</option>
            {watchedDomains.map(d => (
              <option key={d.domain} value={d.domain}>
                {d.domain} ({d.total})
              </option>
            ))}
          </select>
          {/* Show per-domain threat pill if a domain is selected */}
          {filters?.domain && (() => {
            const sel = watchedDomains.find(d => d.domain === filters.domain);
            if (!sel) return null;
            return (
              <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {sel.threatBreakdown.phishing > 0 && (
                  <span style={{ fontSize: 10, fontWeight: 600, background: '#FFF1ED', color: '#9C2B10', borderRadius: 4, padding: '2px 6px' }}>
                    {sel.threatBreakdown.phishing} phishing
                  </span>
                )}
                {sel.threatBreakdown.malware > 0 && (
                  <span style={{ fontSize: 10, fontWeight: 600, background: '#FDF3F3', color: '#8B1A1A', borderRadius: 4, padding: '2px 6px' }}>
                    {sel.threatBreakdown.malware} malware
                  </span>
                )}
                {sel.threatBreakdown.c2 > 0 && (
                  <span style={{ fontSize: 10, fontWeight: 600, background: '#F3EFF9', color: '#5B2C8D', borderRadius: 4, padding: '2px 6px' }}>
                    {sel.threatBreakdown.c2} c2
                  </span>
                )}
                {sel.threatBreakdown.suspicious > 0 && (
                  <span style={{ fontSize: 10, fontWeight: 600, background: '#FFF9ED', color: '#7A4F00', borderRadius: 4, padding: '2px 6px' }}>
                    {sel.threatBreakdown.suspicious} suspicious
                  </span>
                )}
                {sel.blocked > 0 && (
                  <span style={{ fontSize: 10, fontWeight: 600, background: '#FEECEC', color: '#C0392B', borderRadius: 4, padding: '2px 6px' }}>
                    {sel.blocked} blocked
                  </span>
                )}
              </div>
            );
          })()}
        </div>

        <div>
          <label style={{ fontSize: 11, fontWeight: 500, color: '#5C6C75', display: 'block', marginBottom: 4 }}>
            Threat Classification
          </label>
          <select
            value={filters?.classification || ''}
            onChange={e => handleChange('classification', e.target.value)}
            style={selectStyle}
          >
            <option value="">All</option>
            <option value="phishing">Phishing</option>
            <option value="malware">Malware</option>
            <option value="c2">C2</option>
            <option value="suspicious">Suspicious</option>
            <option value="benign">Benign</option>
          </select>
        </div>
        <div>
          <label style={{ fontSize: 11, fontWeight: 500, color: '#5C6C75', display: 'block', marginBottom: 4 }}>
            Status
          </label>
          <select
            value={filters?.status || ''}
            onChange={e => handleChange('status', e.target.value)}
            style={selectStyle}
          >
            <option value="">All</option>
            <option value="blocked">Blocked</option>
            <option value="allowed">Allowed</option>
            <option value="under_review">Under Review</option>
          </select>
        </div>
        <div>
          <label style={{ fontSize: 11, fontWeight: 500, color: '#5C6C75', display: 'block', marginBottom: 4 }}>
            DNS Status
          </label>
          <select
            value={filters?.dnsStatus || ''}
            onChange={e => handleChange('dnsStatus', e.target.value)}
            style={selectStyle}
          >
            <option value="">All</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
            <option value="suspended">Suspended</option>
            <option value="parked">Parked</option>
          </select>
        </div>

        {/* Watched domain quick-picks */}
        {watchedDomains.length > 0 && (
          <div>
            <label style={{ fontSize: 11, fontWeight: 500, color: '#5C6C75', display: 'block', marginBottom: 6 }}>
              Monitored Domains
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {watchedDomains.map(d => (
                <button
                  key={d.domain}
                  onClick={() => handleChange('domain', filters?.domain === d.domain ? '' : d.domain)}
                  style={{
                    textAlign: 'left', padding: '6px 8px', borderRadius: 6,
                    border: `1px solid ${filters?.domain === d.domain ? '#2563EB' : '#E8EDEB'}`,
                    background: filters?.domain === d.domain ? '#EFF6FF' : '#F9FAFB',
                    fontSize: 11, color: filters?.domain === d.domain ? '#1D4ED8' : '#374151',
                    cursor: 'pointer', fontWeight: filters?.domain === d.domain ? 600 : 400,
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  }}
                >
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 120 }}>
                    {d.domain}
                  </span>
                  <span style={{
                    fontSize: 10, fontWeight: 700, borderRadius: 3, padding: '1px 5px',
                    background: d.maxRiskScore >= 75 ? '#FEECEC' : d.maxRiskScore >= 50 ? '#FFF3CD' : '#E8F5E9',
                    color: threatColor(d),
                    flexShrink: 0, marginLeft: 4,
                  }}>
                    {d.total}
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}

        <button
          onClick={() => onChange({})}
          style={{
            padding: '8px', borderRadius: 6,
            border: '1px solid #E8EDEB', background: '#F5F6F7',
            fontSize: 12, color: '#5C6C75', cursor: 'pointer',
            fontWeight: 500,
          }}
        >
          Clear Filters
        </button>
      </div>
    </div>
  );
}
