'use client';

export default function FacetedFilters({ filters, onChange }) {
  const handleChange = (key, value) => {
    onChange({ ...filters, [key]: value || undefined });
  };

  const selectStyle = {
    width: '100%', padding: '8px 12px', borderRadius: 6,
    border: '1px solid #E8EDEB', fontSize: 13, background: '#fff',
    outline: 'none',
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
