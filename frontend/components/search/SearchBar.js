'use client';

import { useState } from 'react';

export default function SearchBar({ onSearch, loading, placeholder }) {
  const [query, setQuery] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (query.trim()) onSearch(query.trim());
  };

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 12 }}>
      <input
        type="text"
        placeholder={placeholder || 'Search threats, URLs, domains...'}
        value={query}
        onChange={e => setQuery(e.target.value)}
        style={{
          flex: 1, padding: '10px 16px', borderRadius: 8,
          border: '1px solid #E8EDEB', fontSize: 14,
          outline: 'none',
        }}
        onFocus={e => e.target.style.borderColor = '#016BF8'}
        onBlur={e => e.target.style.borderColor = '#E8EDEB'}
      />
      <button
        type="submit"
        disabled={loading || !query.trim()}
        style={{
          padding: '10px 24px', borderRadius: 8,
          background: loading ? '#5C6C75' : '#016BF8',
          color: '#fff', border: 'none', fontSize: 13,
          fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer',
        }}
      >
        {loading ? 'Searching...' : 'Search'}
      </button>
    </form>
  );
}
