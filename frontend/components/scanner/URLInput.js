'use client';

import { useState } from 'react';

export default function URLInput({ onSubmit, loading }) {
  const [url, setUrl] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) onSubmit(url.trim());
  };

  return (
    <form onSubmit={handleSubmit} style={{
      background: '#fff', borderRadius: 12, padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, color: '#1a1c1e' }}>
        Submit URL for Analysis
      </h3>
      <div style={{ display: 'flex', gap: 12 }}>
        <input
          type="text"
          placeholder="Enter URL to analyze (e.g. http://suspicious-site.xyz/login)"
          value={url}
          onChange={e => setUrl(e.target.value)}
          style={{
            flex: 1, padding: '12px 16px', borderRadius: 8,
            border: '1px solid #E8EDEB', fontSize: 14,
            outline: 'none', transition: 'border 0.15s',
          }}
          onFocus={e => e.target.style.borderColor = '#016BF8'}
          onBlur={e => e.target.style.borderColor = '#E8EDEB'}
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          style={{
            padding: '12px 32px', borderRadius: 8,
            background: loading ? '#5C6C75' : '#016BF8',
            color: '#fff', border: 'none', fontSize: 14,
            fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer',
            transition: 'background 0.15s',
          }}
        >
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>
    </form>
  );
}
