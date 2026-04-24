'use client';

const FEATURE_CARDS = [
  { key: 'domainAge', label: 'Domain Age', unit: 'days', extract: (r) => r.hostingFlags?.domainAgeDays },
  { key: 'ssl', label: 'SSL Certificate', extract: (r) => r.hostingFlags?.sslValid ? 'Valid ✓' : 'Invalid ✗' },
  { key: 'entropy', label: 'URL Entropy', extract: (r) => r.urlStructure?.entropyScore?.toFixed(2) },
  { key: 'dns', label: 'DNS Status', extract: (r) => r.dnsStatus },
  { key: 'hosting', label: 'Hosting Provider', extract: (r) => r.hostingFlags?.hostingProvider },
  { key: 'geo', label: 'Geo Location', extract: (r) => r.hostingFlags?.geoLocation },
  { key: 'pathDepth', label: 'Path Depth', extract: (r) => r.urlStructure?.pathDepth },
  { key: 'subdomains', label: 'Subdomains', extract: (r) => r.urlStructure?.subdomainCount },
];

function riskColor(val, key) {
  if (key === 'ssl') return val === 'Valid ✓' ? '#00ED64' : '#DB3030';
  if (key === 'dns') return val === 'active' ? '#00ED64' : '#CF4A22';
  return '#016BF8';
}

export default function FeatureBreakdown({ urlRecord }) {
  if (!urlRecord) return null;

  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
        Feature Breakdown
      </h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>
        {FEATURE_CARDS.map(fc => {
          const val = fc.extract(urlRecord);
          return (
            <div key={fc.key} style={{
              padding: '12px 16px', borderRadius: 8,
              background: '#F5F6F7', border: '1px solid #E8EDEB',
            }}>
              <div style={{ fontSize: 11, color: '#5C6C75', fontWeight: 500, marginBottom: 4 }}>
                {fc.label}
              </div>
              <div style={{ fontSize: 18, fontWeight: 700, color: riskColor(val, fc.key) }}>
                {val ?? '—'} {fc.unit && typeof val === 'number' ? fc.unit : ''}
              </div>
            </div>
          );
        })}
      </div>
      {/* Domain info */}
      <div style={{
        marginTop: 16, padding: '10px 16px', borderRadius: 8,
        background: '#F5F6F7', border: '1px solid #E8EDEB',
        fontSize: 12, color: '#5C6C75', display: 'flex', gap: 16, flexWrap: 'wrap',
      }}>
        <span><strong>Domain:</strong> {urlRecord.domain}</span>
        <span><strong>Source:</strong> {urlRecord.source}</span>
        <span><strong>Reviewed by:</strong> {urlRecord.reviewedBy}</span>
      </div>
    </div>
  );
}
