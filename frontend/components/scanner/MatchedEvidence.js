'use client';

import { useState } from 'react';

/* ── colour helpers ─────────────────────────────────────────────────── */
const STATUS_COLORS = {
  blocked:      { bg: '#FFEAE5', color: '#CF4A22', border: '#FFC9B9' },
  under_review: { bg: '#FFF8E6', color: '#944F01', border: '#FFE5A0' },
  allowed:      { bg: '#E3FCF7', color: '#00684A', border: '#C4F3E5' },
};

const riskBadge = (score) => {
  if (score >= 75) return { bg: '#FFEAE5', color: '#DB3030', label: 'Critical' };
  if (score >= 50) return { bg: '#FFF8E6', color: '#944F01', label: 'High' };
  if (score >= 30) return { bg: '#FFF8E6', color: '#944F01', label: 'Medium' };
  return { bg: '#E3FCF7', color: '#00684A', label: 'Low' };
};

/* ── small reusable pill ────────────────────────────────────────────── */
function Pill({ children, bg = '#F5F6F7', color = '#3D4F58' }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 12,
      background: bg, color, fontSize: 10, fontWeight: 600, whiteSpace: 'nowrap',
    }}>
      {children}
    </span>
  );
}

/* ── criteria row inside an expanded card ──────────────────────────── */
function CriteriaRow({ icon, label, status, detail, pills }) {
  const ok = status === 'pass';
  return (
    <div style={{
      display: 'flex', gap: 10, alignItems: 'flex-start',
      padding: '8px 12px', borderRadius: 6,
      background: ok ? '#F7FBF9' : '#FFF7F5',
      border: `1px solid ${ok ? '#E3FCF7' : '#FFC9B9'}`,
    }}>
      <span style={{ fontSize: 15, flexShrink: 0, marginTop: 1 }}>{icon}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: ok ? '#00684A' : '#CF4A22' }}>
          {label}: {ok ? 'PASS' : 'FLAGGED'}
        </div>
        {detail && (
          <div style={{ fontSize: 11, color: '#5C6C75', marginTop: 2, lineHeight: 1.5 }}>
            {detail}
          </div>
        )}
        {pills && pills.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
            {pills.map((p, i) => <Pill key={i} bg={p.bg} color={p.color}>{p.text}</Pill>)}
          </div>
        )}
      </div>
    </div>
  );
}

/* ── build criteria rows from a matched document ──────────────────── */
function buildCriteria(doc) {
  const rows = [];

  // 1. DGA
  const dga = doc.dgaAnalysis;
  if (dga) {
    rows.push({
      icon: '⚙️', label: 'DGA Detection',
      status: dga.isDGA ? 'fail' : 'pass',
      detail: dga.isDGA
        ? `DGA score ${(dga.dgaScore * 100).toFixed(0)}% — domain appears algorithmically generated`
        : `DGA score ${(dga.dgaScore * 100).toFixed(0)}% — below threshold`,
      pills: [
        { text: `Consonant: ${(dga.consonantRatio * 100).toFixed(0)}%`, bg: '#F5F6F7', color: '#3D4F58' },
        { text: `Bigram: ${(dga.bigramLegitimacy * 100).toFixed(0)}%`, bg: '#F5F6F7', color: '#3D4F58' },
        { text: `Length: ${dga.domainLength}`, bg: '#F5F6F7', color: '#3D4F58' },
      ],
    });
  }

  // 2. Homoglyph
  const hg = doc.homoglyphAnalysis;
  if (hg) {
    rows.push({
      icon: '👁️', label: 'Homoglyph / Typosquat',
      status: hg.hasHomoglyphs ? 'fail' : 'pass',
      detail: hg.hasHomoglyphs
        ? `Visual impersonation of "${hg.targetDomain || 'unknown'}" (${(hg.visualSimilarity * 100).toFixed(0)}% similarity)`
        : `No visual tricks detected (similarity ${(hg.visualSimilarity * 100).toFixed(0)}%)`,
      pills: hg.homoglyphSignals?.map(s => ({ text: s.substring(0, 60), bg: '#FFF8E6', color: '#944F01' })) || [],
    });
  }

  // 3. Brand Impersonation
  const bi = doc.brandImpersonation;
  if (bi) {
    const isThreat = !bi.is_exact_match && bi.edit_distance > 0 && bi.edit_distance <= 3;
    rows.push({
      icon: '🏛️', label: 'Brand Impersonation',
      status: isThreat ? 'fail' : 'pass',
      detail: bi.is_exact_match
        ? `Exact match: ${bi.known_domain} (${bi.closest_brand})`
        : isThreat
          ? `${bi.edit_distance} char(s) from "${bi.known_domain}" (${bi.closest_brand})`
          : `Nearest brand: ${bi.known_domain} (distance ${bi.edit_distance})`,
      pills: bi.is_exact_match
        ? [{ text: 'Legitimate Domain', bg: '#E3FCF7', color: '#00684A' }]
        : isThreat
          ? [{ text: `Edit Distance: ${bi.edit_distance}`, bg: '#FFEAE5', color: '#CF4A22' }]
          : [],
    });
  }

  // 4. Structural Bypass
  const st = doc.structuralAnalysis;
  if (st) {
    const hasBypass = st.bypassTechniques?.length > 0;
    rows.push({
      icon: '🛡️', label: 'Structural Bypass',
      status: hasBypass ? 'fail' : 'pass',
      detail: hasBypass
        ? `${st.bypassTechniques.length} technique(s) detected — score ${(st.structuralScore * 100).toFixed(0)}%`
        : 'No bypass techniques detected',
      pills: (st.bypassTechniques || []).map(t => ({
        text: t.replace(/_/g, ' ').toUpperCase(),
        bg: '#FFEAE5', color: '#CF4A22',
      })),
    });
  }

  // 5. TLD Risk
  const tld = doc.tldRisk;
  if (tld) {
    rows.push({
      icon: '🌐', label: 'TLD Risk',
      status: tld.tldRisk === 'high' ? 'fail' : 'pass',
      detail: tld.tldNote || `TLD risk: ${tld.tldRisk}`,
      pills: [{ text: `Risk: ${tld.tldRisk}`, bg: tld.tldRisk === 'high' ? '#FFEAE5' : '#E3FCF7', color: tld.tldRisk === 'high' ? '#CF4A22' : '#00684A' }],
    });
  }

  // 6. Hosting / Infrastructure
  const hf = doc.hostingFlags;
  if (hf) {
    const risky = !hf.sslValid || hf.domainAgeDays < 30;
    rows.push({
      icon: '🏗️', label: 'Hosting & Infrastructure',
      status: risky ? 'fail' : 'pass',
      detail: `${hf.hostingProvider || 'Unknown'} · ${hf.geoLocation || '??'} · SSL ${hf.sslValid ? '✓' : '✗'} · Age ${hf.domainAgeDays}d`,
      pills: [
        hf.isSharedHosting && { text: 'Shared Hosting', bg: '#FFF8E6', color: '#944F01' },
        hf.isCloudHosted && { text: 'Cloud', bg: '#F5F6F7', color: '#3D4F58' },
        !hf.sslValid && { text: 'No SSL', bg: '#FFEAE5', color: '#CF4A22' },
        hf.domainAgeDays < 30 && { text: `New (${hf.domainAgeDays}d)`, bg: '#FFEAE5', color: '#CF4A22' },
      ].filter(Boolean),
    });
  }

  return rows;
}

/* ── single expandable matched document card ──────────────────────── */
function MatchedDocCard({ doc, index, type }) {
  const [expanded, setExpanded] = useState(false);
  const sc = STATUS_COLORS[doc.status] || STATUS_COLORS.allowed;
  const rb = riskBadge(doc.riskScore || 0);
  const criteria = expanded ? buildCriteria(doc) : [];
  const passCount = criteria.filter(c => c.status === 'pass').length;
  const failCount = criteria.filter(c => c.status === 'fail').length;

  return (
    <div style={{
      borderRadius: 10, border: `1px solid ${sc.border}`,
      background: '#fff', overflow: 'hidden',
      boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
    }}>
      {/* Header — always visible */}
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '12px 16px', cursor: 'pointer',
          display: 'flex', alignItems: 'center', gap: 12,
          background: expanded ? '#FAFBFC' : '#fff',
          borderBottom: expanded ? '1px solid #E8EDEB' : 'none',
        }}
      >
        <span style={{ fontSize: 12, fontWeight: 700, color: '#889397', width: 24 }}>
          #{index + 1}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontSize: 13, fontWeight: 600, color: '#1a1c1e',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {doc.url}
          </div>
          <div style={{ fontSize: 11, color: '#5C6C75', marginTop: 2 }}>
            {doc.domain || '—'} · {doc.threatClassification || type || '—'}
            {doc.source ? ` · ${doc.source}` : ''}
          </div>
        </div>
        <Pill bg={sc.bg} color={sc.color}>{(doc.status || '').replace('_', ' ').toUpperCase()}</Pill>
        <Pill bg={rb.bg} color={rb.color}>Risk: {doc.riskScore ?? '—'}</Pill>
        <div style={{
          padding: '4px 12px', borderRadius: 20, whiteSpace: 'nowrap',
          background: '#E8EDEB', color: '#016BF8', fontSize: 12, fontWeight: 700,
        }}>
          {((doc.score || 0) * 100).toFixed(1)}%
        </div>
        <span style={{ fontSize: 14, color: '#889397', transition: 'transform .2s', transform: expanded ? 'rotate(180deg)' : 'rotate(0)' }}>
          ▾
        </span>
      </div>

      {/* Expanded detail — criteria breakdown */}
      {expanded && (
        <div style={{ padding: 16 }}>
          {/* Summary bar */}
          <div style={{
            display: 'flex', gap: 12, marginBottom: 12,
            padding: '8px 14px', borderRadius: 8, background: '#F5F6F7',
            fontSize: 12, fontWeight: 600, color: '#3D4F58',
          }}>
            <span>🔍 {criteria.length} checks</span>
            <span style={{ color: '#00684A' }}>✓ {passCount} passed</span>
            <span style={{ color: '#CF4A22' }}>✗ {failCount} flagged</span>
            {doc.summaryText && (
              <span style={{ marginLeft: 'auto', fontWeight: 400, color: '#889397', fontSize: 11, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {doc.summaryText.substring(0, 80)}...
              </span>
            )}
          </div>

          {/* Criteria rows */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {criteria.map((c, i) => <CriteriaRow key={i} {...c} />)}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── threat intel card (different schema) ─────────────────────────── */
function IntelDocCard({ doc, index }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div style={{
      borderRadius: 10, border: '1px solid #FFE5A0',
      background: '#fff', overflow: 'hidden',
      boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
    }}>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '12px 16px', cursor: 'pointer',
          display: 'flex', alignItems: 'center', gap: 12,
          background: expanded ? '#FFFDF5' : '#fff',
          borderBottom: expanded ? '1px solid #FFE5A0' : 'none',
        }}
      >
        <span style={{ fontSize: 12, fontWeight: 700, color: '#889397', width: 24 }}>
          #{index + 1}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontSize: 13, fontWeight: 600, color: '#1a1c1e',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {doc.url}
          </div>
          <div style={{ fontSize: 11, color: '#5C6C75', marginTop: 2 }}>
            {doc.feedName || '—'} · {doc.threatType || '—'}
          </div>
        </div>
        <Pill bg="#FFF8E6" color="#944F01">{(doc.threatType || 'unknown').toUpperCase()}</Pill>
        <div style={{
          padding: '4px 12px', borderRadius: 20, whiteSpace: 'nowrap',
          background: '#FFEAE5', color: '#CF4A22', fontSize: 12, fontWeight: 700,
        }}>
          {((doc.score || 0) * 100).toFixed(1)}%
        </div>
        <span style={{ fontSize: 14, color: '#889397', transition: 'transform .2s', transform: expanded ? 'rotate(180deg)' : 'rotate(0)' }}>
          ▾
        </span>
      </div>

      {expanded && (
        <div style={{ padding: 16 }}>
          <div style={{
            fontSize: 12, color: '#3D4F58', lineHeight: 1.6,
            padding: '10px 14px', borderRadius: 8,
            background: '#FFF8E6', border: '1px solid #FFE5A0',
          }}>
            <strong>Description:</strong> {doc.description || 'No description available.'}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
            {doc.feedName && <Pill bg="#F5F6F7" color="#3D4F58">Feed: {doc.feedName}</Pill>}
            {doc.reportedDate && <Pill bg="#F5F6F7" color="#3D4F58">Reported: {new Date(doc.reportedDate).toLocaleDateString()}</Pill>}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── main export ──────────────────────────────────────────────────── */
export default function MatchedEvidence({ similarThreats, threatIntelMatches }) {
  const hasThreats = similarThreats?.length > 0;
  const hasIntel = threatIntelMatches?.length > 0;

  if (!hasThreats && !hasIntel) return null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Similar URLs from vector search */}
      {hasThreats && (
        <div style={{
          background: '#fff', borderRadius: 12, padding: 24,
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <h3 style={{ fontSize: 16, fontWeight: 600, color: '#1a1c1e', margin: 0 }}>
              🔗 Matched Documents — Vector Search ({similarThreats.length})
            </h3>
            <span style={{ fontSize: 11, color: '#889397' }}>
              Click any row to expand the full analysis report
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {similarThreats.map((t, i) => (
              <MatchedDocCard key={t._id || i} doc={t} index={i} type="vector_match" />
            ))}
          </div>
        </div>
      )}

      {/* Threat intel feed matches */}
      {hasIntel && (
        <div style={{
          background: '#fff', borderRadius: 12, padding: 24,
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <h3 style={{ fontSize: 16, fontWeight: 600, color: '#1a1c1e', margin: 0 }}>
              📡 Matched Documents — Threat Intelligence ({threatIntelMatches.length})
            </h3>
            <span style={{ fontSize: 11, color: '#889397' }}>
              Click any row to see the full intel report
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {threatIntelMatches.map((t, i) => (
              <IntelDocCard key={t._id || i} doc={t} index={i} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
