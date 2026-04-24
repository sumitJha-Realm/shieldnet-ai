'use client';

import { useState } from 'react';

const STATUS_BADGE = {
  blocked: { bg: '#FFEAE5', color: '#CF4A22' },
  allowed: { bg: '#E3FCF7', color: '#00684A' },
  under_review: { bg: '#FFF8E6', color: '#944F01' },
};

const THREAT_BADGE = {
  phishing: { bg: '#FFEAE5', color: '#CF4A22' },
  malware: { bg: '#FFEAE5', color: '#DB3030' },
  c2: { bg: '#F1E3FF', color: '#8B5CF6' },
  suspicious: { bg: '#FFF8E6', color: '#944F01' },
  benign: { bg: '#E3FCF7', color: '#00684A' },
};

export default function ThreatTable({ urls, onRowClick }) {
  const [copiedId, setCopiedId] = useState(null);

  const handleCopy = (e, url) => {
    e.stopPropagation();
    navigator.clipboard.writeText(url.url).then(() => {
      setCopiedId(url._id);
      setTimeout(() => setCopiedId(null), 1500);
    });
  };

  return (
    <div style={{
      background: '#fff', borderRadius: 12,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      overflow: 'hidden',
    }}>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: '#F5F6F7', borderBottom: '2px solid #E8EDEB' }}>
              <th style={{ textAlign: 'left', padding: '12px 16px', color: '#5C6C75', fontWeight: 600 }}>URL</th>
              <th style={{ textAlign: 'left', padding: '12px 16px', color: '#5C6C75', fontWeight: 600 }}>Domain</th>
              <th style={{ textAlign: 'left', padding: '12px 16px', color: '#5C6C75', fontWeight: 600 }}>Threat</th>
              <th style={{ textAlign: 'left', padding: '12px 16px', color: '#5C6C75', fontWeight: 600 }}>Risk</th>
              <th style={{ textAlign: 'left', padding: '12px 16px', color: '#5C6C75', fontWeight: 600 }}>DNS</th>
              <th style={{ textAlign: 'left', padding: '12px 16px', color: '#5C6C75', fontWeight: 600 }}>Status</th>
              <th style={{ textAlign: 'left', padding: '12px 16px', color: '#5C6C75', fontWeight: 600 }}>Date</th>
            </tr>
          </thead>
          <tbody>
            {(urls || []).map((url, i) => {
              const threat = THREAT_BADGE[url.threatClassification] || THREAT_BADGE.suspicious;
              const status = STATUS_BADGE[url.status] || STATUS_BADGE.under_review;
              return (
                <tr
                  key={url._id || i}
                  onClick={() => onRowClick?.(url)}
                  style={{
                    borderBottom: '1px solid #F5F6F7',
                    cursor: 'pointer',
                    transition: 'background 0.1s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = '#F9FAFB'}
                  onMouseLeave={e => e.currentTarget.style.background = ''}
                >
                  <td style={{ padding: '10px 16px', maxWidth: 280 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1, minWidth: 0 }}>
                        {url.url}
                      </span>
                      <button
                        onClick={(e) => handleCopy(e, url)}
                        title="Copy URL"
                        style={{
                          flexShrink: 0, border: 'none', background: 'none',
                          cursor: 'pointer', padding: '2px 4px', borderRadius: 4,
                          fontSize: 14, lineHeight: 1, color: copiedId === url._id ? '#00684A' : '#889397',
                          transition: 'color .15s',
                        }}
                        onMouseEnter={e => { if (copiedId !== url._id) e.currentTarget.style.color = '#016BF8'; }}
                        onMouseLeave={e => { if (copiedId !== url._id) e.currentTarget.style.color = '#889397'; }}
                      >
                        {copiedId === url._id ? '✓' : '📋'}
                      </button>
                    </div>
                  </td>
                  <td style={{ padding: '10px 16px' }}>{url.domain}</td>
                  <td style={{ padding: '10px 16px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4,
                      fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
                      background: threat.bg, color: threat.color,
                    }}>{url.threatClassification}</span>
                  </td>
                  <td style={{ padding: '10px 16px', fontWeight: 700, color: url.riskScore >= 75 ? '#DB3030' : url.riskScore >= 50 ? '#FFC010' : '#00684A' }}>
                    {url.riskScore}
                  </td>
                  <td style={{ padding: '10px 16px' }}>{url.dnsStatus}</td>
                  <td style={{ padding: '10px 16px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4,
                      fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
                      background: status.bg, color: status.color,
                    }}>{url.status}</span>
                  </td>
                  <td style={{ padding: '10px 16px', color: '#5C6C75', fontSize: 12 }}>
                    {url.createdAt ? new Date(url.createdAt).toLocaleDateString() : '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {(!urls || urls.length === 0) && (
          <div style={{ textAlign: 'center', padding: 48, color: '#5C6C75' }}>
            No threats found. Use the search or seed the database.
          </div>
        )}
      </div>
    </div>
  );
}
