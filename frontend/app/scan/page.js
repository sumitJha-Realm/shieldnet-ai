'use client';

import { useState } from 'react';
import AgenticPanel from '../../components/scanner/AgenticPanel';
import URLInput from '../../components/scanner/URLInput';
import RiskGauge from '../../components/scanner/RiskGauge';
import FeatureBreakdown from '../../components/scanner/FeatureBreakdown';
import SimilarThreats from '../../components/scanner/SimilarThreats';
import MatchedEvidence from '../../components/scanner/MatchedEvidence';
import ThreatGraph from '../../components/scanner/ThreatGraph';
import RiskBreakdownChart from '../../components/scanner/RiskBreakdownChart';
import { scanAgenticURL, scanURL, updateURLStatus } from '../../lib/api';

/* ── STATUS_PILL colours ─────────────────────────────────────────── */
const DOC_STATUS_COLORS = {
  blocked:      { bg: '#FFEAE5', color: '#CF4A22' },
  under_review: { bg: '#FFF8E6', color: '#944F01' },
  allowed:      { bg: '#E3FCF7', color: '#00684A' },
};

/* ── Inline matched‑document card for a single reason ────────────── */
function ReasonDocCard({ doc }) {
  const sc = DOC_STATUS_COLORS[doc.status] || DOC_STATUS_COLORS.allowed;
  const isIntel = !!doc.feedName;

  return (
    <div style={{
      padding: '8px 12px', borderRadius: 8,
      background: '#FAFBFC', border: '1px solid #E8EDEB',
      display: 'flex', alignItems: 'center', gap: 10,
      fontSize: 12,
    }}>
      <span style={{ fontSize: 14, flexShrink: 0 }}>{isIntel ? '📡' : '📄'}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontWeight: 600, color: '#1a1c1e',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {doc.url}
        </div>
        <div style={{ fontSize: 11, color: '#5C6C75', marginTop: 1 }}>
          {isIntel
            ? `${doc.feedName || '—'} · ${doc.threatType || '—'}`
            : `${doc.domain || '—'} · ${doc.threatClassification || '—'} · Risk: ${doc.riskScore ?? '—'}`
          }
          {doc.brandImpersonation && !doc.brandImpersonation.is_exact_match && doc.brandImpersonation.edit_distance > 0 && (
            ` · Brand: ${doc.brandImpersonation.closest_brand} (dist ${doc.brandImpersonation.edit_distance})`
          )}
          {doc.dgaAnalysis?.isDGA && ` · DGA ${(doc.dgaAnalysis.dgaScore * 100).toFixed(0)}%`}
        </div>
        {isIntel && doc.description && (
          <div style={{ fontSize: 10, color: '#889397', marginTop: 2, lineHeight: 1.4 }}>
            {doc.description.substring(0, 140)}{doc.description.length > 140 ? '…' : ''}
          </div>
        )}
      </div>
      {doc.status && (
        <span style={{
          padding: '2px 8px', borderRadius: 10,
          background: sc.bg, color: sc.color,
          fontSize: 10, fontWeight: 700, whiteSpace: 'nowrap',
        }}>
          {doc.status.replace('_', ' ').toUpperCase()}
        </span>
      )}
      {doc.score != null && (
        <span style={{
          padding: '2px 8px', borderRadius: 10,
          background: '#E8EDEB', color: '#016BF8',
          fontSize: 10, fontWeight: 700, whiteSpace: 'nowrap',
        }}>
          {(doc.score * 100).toFixed(1)}%
        </span>
      )}
    </div>
  );
}

/* ── Single expandable reason row ────────────────────────────────── */
function ReasonRow({ reason, status }) {
  const [expanded, setExpanded] = useState(false);
  // Support both new structured { text, matchedDocs } and legacy string reasons
  const text = typeof reason === 'string' ? reason : reason.text;
  const docs = (typeof reason === 'object' && reason.matchedDocs) || [];
  const hasDocs = docs.length > 0;
  const isSubReason = text?.startsWith('  ↳');

  const bgMap  = { blocked: '#FFF5F5', under_review: '#FFF8E6' };
  const brdMap = { blocked: '#FFC9B9', under_review: '#FFE5A0' };
  const dotMap = { blocked: '#CF4A22', under_review: '#944F01' };
  const symMap = { blocked: '●', under_review: '▲' };

  return (
    <div>
      <div
        onClick={hasDocs ? () => setExpanded(e => !e) : undefined}
        style={{
          padding: '10px 14px', borderRadius: 8,
          background: bgMap[status] || '#F5F6F7',
          border: `1px solid ${brdMap[status] || '#E8EDEB'}`,
          fontSize: 13, color: '#3D4F58', lineHeight: 1.5,
          display: 'flex', alignItems: 'flex-start', gap: 8,
          cursor: hasDocs ? 'pointer' : 'default',
        }}
      >
        {!isSubReason && (
          <span style={{ color: dotMap[status] || '#5C6C75', fontWeight: 700, flexShrink: 0 }}>
            {symMap[status] || '○'}
          </span>
        )}
        <span style={{ flex: 1 }}>{text}</span>
        {hasDocs && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            padding: '2px 8px', borderRadius: 10,
            background: '#E8EDEB', color: '#016BF8',
            fontSize: 10, fontWeight: 700, whiteSpace: 'nowrap', flexShrink: 0,
            transition: 'transform .2s',
          }}>
            📂 {docs.length} doc{docs.length > 1 ? 's' : ''}
            <span style={{ transform: expanded ? 'rotate(180deg)' : 'rotate(0)', display: 'inline-block', transition: 'transform .2s' }}>▾</span>
          </span>
        )}
      </div>
      {expanded && hasDocs && (
        <div style={{
          marginTop: 4, marginLeft: 24,
          display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          <div style={{
            fontSize: 10, fontWeight: 600, color: '#889397',
            padding: '4px 0', textTransform: 'uppercase', letterSpacing: '0.5px',
          }}>
            Matched MongoDB Documents
          </div>
          {docs.map((doc, j) => (
            <ReasonDocCard key={doc._id || j} doc={doc} />
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Full Analysis Summary block ─────────────────────────────────── */
function AnalysisSummary({ reasons, riskFactors, status }) {
  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    }}>
      <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
        Analysis Summary
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {reasons.map((reason, i) => (
          <ReasonRow key={i} reason={reason} status={status} />
        ))}
      </div>
      {/* Risk factor badges */}
      {riskFactors && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 16 }}>
          {riskFactors.vectorSimilarity > 0 && (
            <span style={{ padding: '4px 10px', borderRadius: 16, background: '#E8EDEB', fontSize: 11, color: '#3D4F58', fontWeight: 600 }}>
              Vector Similarity: {riskFactors.vectorSimilarity}%
            </span>
          )}
          {riskFactors.threatIntelHits > 0 && (
            <span style={{ padding: '4px 10px', borderRadius: 16, background: '#FFEAE5', fontSize: 11, color: '#CF4A22', fontWeight: 600 }}>
              Intel Hits: {riskFactors.threatIntelHits}
            </span>
          )}
          {riskFactors.blockedSimilar > 0 && (
            <span style={{ padding: '4px 10px', borderRadius: 16, background: '#FFEAE5', fontSize: 11, color: '#DB3030', fontWeight: 600 }}>
              Blocked Matches: {riskFactors.blockedSimilar}
            </span>
          )}
          {riskFactors.dgaDetected && (
            <span style={{ padding: '4px 10px', borderRadius: 16, background: '#FFEAE5', fontSize: 11, color: '#CF4A22', fontWeight: 600 }}>
              ⚙️ DGA Detected
            </span>
          )}
          {riskFactors.homoglyphDetected && (
            <span style={{ padding: '4px 10px', borderRadius: 16, background: '#FFF8E6', fontSize: 11, color: '#944F01', fontWeight: 600 }}>
              👁️ Homoglyph Attack
            </span>
          )}
          {riskFactors.bypassTechniques?.length > 0 && (
            <span style={{ padding: '4px 10px', borderRadius: 16, background: '#FFEAE5', fontSize: 11, color: '#CF4A22', fontWeight: 600 }}>
              🛡️ {riskFactors.bypassTechniques.length} Bypass(es)
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export default function ScanPage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [scanMode, setScanMode] = useState('agentic');

  const handleScan = async (url) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = scanMode === 'agentic' ? await scanAgenticURL(url) : await scanURL(url);
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Scan failed. Ensure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async (id, status) => {
    try {
      const res = await updateURLStatus(id, status);
      const updatedRecord = res.data || {};
      const statusNote = updatedRecord.statusNote || null;
      setResult(prev => ({
        ...prev,
        urlRecord: { ...prev.urlRecord, status, statusNote },
        statusOverrideNote: null,
      }));
    } catch (err) {
      console.error('Status update failed:', err);
    }
  };

  const rec = result?.urlRecord;
  const action = result?.recommendedAction;

  const ACTION_STYLES = {
    block: { bg: '#FFEAE5', color: '#CF4A22', label: 'RECOMMENDED: Block this URL immediately' },
    review: { bg: '#FFF8E6', color: '#944F01', label: 'RECOMMENDED: Manual review required' },
    allow: { bg: '#E3FCF7', color: '#00684A', label: 'RECOMMENDED: URL appears safe to allow' },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        alignSelf: 'flex-start',
        padding: 6,
        background: '#F5F6F7',
        borderRadius: 999,
        border: '1px solid #E8EDEB',
      }}>
        {[
          { key: 'agentic', label: 'Pipeline + Foundry' },
          { key: 'pipeline', label: 'Pipeline only' },
        ].map((mode) => {
          const active = scanMode === mode.key;
          return (
            <button
              key={mode.key}
              onClick={() => setScanMode(mode.key)}
              style={{
                border: 'none',
                borderRadius: 999,
                padding: '10px 16px',
                fontSize: 13,
                fontWeight: 700,
                cursor: 'pointer',
                background: active ? '#1A1C1E' : 'transparent',
                color: active ? '#fff' : '#5C6C75',
              }}
            >
              {mode.label}
            </button>
          );
        })}
      </div>

      <URLInput onSubmit={handleScan} loading={loading} />

      {error && (
        <div style={{
          padding: '12px 20px', borderRadius: 8,
          background: '#FFEAE5', color: '#CF4A22', fontSize: 13,
          border: '1px solid #FFC9B9',
        }}>
          {error}
        </div>
      )}

      {result && (
        <>
          {/* Status Note Banner — shows when URL has an authoritative status note */}
          {(result.statusOverrideNote || rec.statusNote) && (
            <div style={{
              padding: '14px 20px', borderRadius: 10,
              background: rec.status === 'blocked' ? '#FFEAE5'
                : rec.status === 'allowed' ? '#E3FCF7' : '#FFF8E6',
              border: `1px solid ${rec.status === 'blocked' ? '#CF4A22'
                : rec.status === 'allowed' ? '#00684A' : '#944F01'}44`,
              display: 'flex', alignItems: 'center', gap: 10,
              fontSize: 13, fontWeight: 600,
              color: rec.status === 'blocked' ? '#CF4A22'
                : rec.status === 'allowed' ? '#00684A' : '#944F01',
            }}>
              <span style={{ fontSize: 18, flexShrink: 0 }}>
                {rec.status === 'blocked' ? '🔒' : rec.status === 'allowed' ? '✅' : '📋'}
              </span>
              <span>{result.statusOverrideNote || rec.statusNote}</span>
            </div>
          )}

          {/* Threat Status Banner */}
          {rec.status === 'blocked' && (
            <div style={{
              padding: '20px 24px', borderRadius: 12,
              background: 'linear-gradient(135deg, #DB3030 0%, #CF4A22 100%)',
              color: '#fff', border: '1px solid rgba(255,255,255,0.1)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
                <span style={{ fontSize: 28 }}>⛔</span>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>THREAT DETECTED — URL BLOCKED</div>
                  <div style={{ fontSize: 13, opacity: 0.9, marginTop: 2 }}>
                    Classification: <strong>{rec.threatClassification?.toUpperCase()}</strong> · Risk Score: <strong>{rec.riskScore}/100</strong>
                  </div>
                </div>
              </div>
              {result.analysisSummary?.verdict && (
                <div style={{ fontSize: 13, opacity: 0.95, lineHeight: 1.5, marginTop: 4 }}>
                  {result.analysisSummary.verdict}
                </div>
              )}
            </div>
          )}

          {rec.status === 'under_review' && (
            <div style={{
              padding: '20px 24px', borderRadius: 12,
              background: 'linear-gradient(135deg, #944F01 0%, #B8860B 100%)',
              color: '#fff', border: '1px solid rgba(255,255,255,0.1)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
                <span style={{ fontSize: 28 }}>⚠️</span>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>SUSPICIOUS URL — UNDER REVIEW</div>
                  <div style={{ fontSize: 13, opacity: 0.9, marginTop: 2 }}>
                    Classification: <strong>{rec.threatClassification?.toUpperCase()}</strong> · Risk Score: <strong>{rec.riskScore}/100</strong>
                  </div>
                </div>
              </div>
              {result.analysisSummary?.verdict && (
                <div style={{ fontSize: 13, opacity: 0.95, lineHeight: 1.5, marginTop: 4 }}>
                  {result.analysisSummary.verdict}
                </div>
              )}
            </div>
          )}

          {rec.status === 'allowed' && (
            <div style={{
              padding: '20px 24px', borderRadius: 12,
              background: 'linear-gradient(135deg, #00684A 0%, #00ED64 100%)',
              color: '#fff', border: '1px solid rgba(255,255,255,0.1)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ fontSize: 28 }}>✅</span>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>URL APPEARS SAFE</div>
                  <div style={{ fontSize: 13, opacity: 0.9, marginTop: 2 }}>
                    Classification: <strong>{rec.threatClassification?.toUpperCase()}</strong> · Risk Score: <strong>{rec.riskScore}/100</strong>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Analysis Summary — why it was flagged */}
          {result.analysisSummary?.reasons?.length > 0 && (
            <AnalysisSummary
              reasons={result.analysisSummary.reasons}
              riskFactors={result.analysisSummary.riskFactors}
              status={rec.status}
            />
          )}

          {/* Recommended Action */}
          {action && (
            <div style={{
              padding: '14px 24px', borderRadius: 10,
              background: ACTION_STYLES[action]?.bg || '#F5F6F7',
              color: ACTION_STYLES[action]?.color || '#5C6C75',
              fontWeight: 600, fontSize: 14,
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <span>{ACTION_STYLES[action]?.label}</span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  onClick={() => handleStatusChange(rec._id, 'blocked')}
                  style={{
                    padding: '6px 16px', borderRadius: 6,
                    background: '#CF4A22', color: '#fff', border: 'none',
                    fontSize: 12, fontWeight: 600, cursor: 'pointer',
                  }}
                >
                  Confirm Block
                </button>
                <button
                  onClick={() => handleStatusChange(rec._id, 'allowed')}
                  style={{
                    padding: '6px 16px', borderRadius: 6,
                    background: '#00684A', color: '#fff', border: 'none',
                    fontSize: 12, fontWeight: 600, cursor: 'pointer',
                  }}
                >
                  Mark as Safe
                </button>
              </div>
            </div>
          )}

          <div style={{
            display: 'grid',
            gridTemplateColumns: result.agenticAnalysis ? 'minmax(0, 1.1fr) minmax(320px, 0.9fr)' : 'minmax(0, 1fr)',
            gap: 24,
          }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 24 }}>
                <RiskGauge score={rec.riskScore} level={result.riskLevel} />
                <FeatureBreakdown urlRecord={rec} />
              </div>
            </div>

            {result.agenticAnalysis && (
              <AgenticPanel
                pipelineScore={rec.riskScore}
                pipelineStatus={rec.status}
                agenticAnalysis={result.agenticAnalysis}
              />
            )}
          </div>

          {/* Risk Score Breakdown Chart */}
          {result.riskBreakdown && result.riskBreakdown.length > 0 && (
            <RiskBreakdownChart breakdown={result.riskBreakdown} totalScore={rec.riskScore} />
          )}

          {/* Waterfall Enforcement Tier + Latency */}
          {result.waterfallTier && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 12, padding: '10px 20px',
              borderRadius: 8, background: '#F5F6F7', border: '1px solid #E8EDEB',
            }}>
              <span style={{
                padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 700,
                background: result.waterfallTier === 'L1_CACHE' ? '#E3FCF7' : result.waterfallTier === 'L2_DATABASE' ? '#E8EDEB' : '#FFF8E6',
                color: result.waterfallTier === 'L1_CACHE' ? '#00684A' : result.waterfallTier === 'L2_DATABASE' ? '#3D4F58' : '#944F01',
              }}>
                {result.waterfallTier === 'L1_CACHE' ? '⚡ L1 Cache Hit' : result.waterfallTier === 'L2_DATABASE' ? '💾 L2 Database Hit' : '🔬 L3 Full Pipeline'}
              </span>
              <span style={{ fontSize: 12, color: '#5C6C75' }}>
                Latency: <strong>{result.latencyMs}ms</strong>
              </span>
              <span style={{ fontSize: 11, color: '#889397', marginLeft: 'auto' }}>
                Waterfall: Local Cache → MongoDB → Vector DB + AI
              </span>
            </div>
          )}

          {/* Semantic Features Grid */}
          {result.analysisSummary?.semanticFeatures && (
            <div style={{
              background: '#fff', borderRadius: 12, padding: 24,
              boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
            }}>
              <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#1a1c1e' }}>
                Semantic Feature Analysis (5 Embedding Dimensions)
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                {[
                  { key: 'visualSimilarity', label: 'Visual Similarity', desc: 'Homoglyph / typosquat detection', icon: '👁️' },
                  { key: 'tldEntropy', label: 'TLD Risk', desc: 'Top-level domain reputation', icon: '🌐' },
                  { key: 'consonantRatio', label: 'Consonant Ratio', desc: 'DGA character composition', icon: '🔤' },
                  { key: 'domainTokenization', label: 'Structural Score', desc: 'URL pattern decomposition', icon: '🧩' },
                  { key: 'asnReputation', label: 'ASN Reputation', desc: 'Infrastructure risk signal', icon: '🏗️' },
                  { key: 'dgaScore', label: 'DGA Score', desc: 'Algorithmic domain confidence', icon: '⚙️' },
                  { key: 'bigramLegitimacy', label: 'Bigram Legitimacy', desc: 'English language probability', icon: '📊' },
                ].map(feat => {
                  const val = result.analysisSummary.semanticFeatures[feat.key] || 0;
                  const pct = feat.key === 'bigramLegitimacy' ? val : val;
                  const barColor = feat.key === 'bigramLegitimacy'
                    ? (val > 0.5 ? '#00ED64' : val > 0.25 ? '#FFB800' : '#DB3030')
                    : (val > 0.6 ? '#DB3030' : val > 0.3 ? '#FFB800' : '#00ED64');
                  return (
                    <div key={feat.key} style={{
                      padding: '14px 16px', borderRadius: 8,
                      background: '#F5F6F7', border: '1px solid #E8EDEB',
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <span style={{ fontSize: 12, fontWeight: 600, color: '#1a1c1e' }}>
                          {feat.icon} {feat.label}
                        </span>
                        <span style={{ fontSize: 14, fontWeight: 700, color: barColor }}>
                          {(pct * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div style={{ height: 6, borderRadius: 3, background: '#E8EDEB', overflow: 'hidden' }}>
                        <div style={{ height: '100%', borderRadius: 3, background: barColor, width: `${Math.min(pct * 100, 100)}%`, transition: 'width 0.5s' }} />
                      </div>
                      <div style={{ fontSize: 10, color: '#889397', marginTop: 4 }}>{feat.desc}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* DGA + Homoglyph + Structural Detail Cards */}
          {(rec.dgaAnalysis?.isDGA || rec.homoglyphAnalysis?.hasHomoglyphs || rec.structuralAnalysis?.bypassTechniques?.length > 0) && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              {rec.dgaAnalysis?.isDGA && (
                <div style={{
                  background: '#fff', borderRadius: 12, padding: 20,
                  boxShadow: '0 1px 3px rgba(0,0,0,0.08)', border: '2px solid #FFEAE5',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                    <span style={{ fontSize: 20 }}>⚙️</span>
                    <h4 style={{ fontSize: 14, fontWeight: 700, color: '#CF4A22' }}>DGA Detection</h4>
                    <span style={{
                      marginLeft: 'auto', padding: '2px 8px', borderRadius: 12,
                      background: '#FFEAE5', color: '#CF4A22', fontSize: 11, fontWeight: 700,
                    }}>
                      Score: {(rec.dgaAnalysis.dgaScore * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: '#3D4F58', lineHeight: 1.6 }}>
                    {rec.dgaAnalysis.dgaSignals?.map((s, i) => (
                      <div key={i} style={{ marginBottom: 4 }}>• {s}</div>
                    ))}
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
                    <span style={{ padding: '2px 8px', borderRadius: 10, background: '#F5F6F7', fontSize: 10, color: '#5C6C75' }}>
                      Consonant: {(rec.dgaAnalysis.consonantRatio * 100).toFixed(0)}%
                    </span>
                    <span style={{ padding: '2px 8px', borderRadius: 10, background: '#F5F6F7', fontSize: 10, color: '#5C6C75' }}>
                      Bigram: {(rec.dgaAnalysis.bigramLegitimacy * 100).toFixed(0)}%
                    </span>
                    <span style={{ padding: '2px 8px', borderRadius: 10, background: '#F5F6F7', fontSize: 10, color: '#5C6C75' }}>
                      Length: {rec.dgaAnalysis.domainLength}
                    </span>
                  </div>
                </div>
              )}

              {rec.homoglyphAnalysis?.hasHomoglyphs && (
                <div style={{
                  background: '#fff', borderRadius: 12, padding: 20,
                  boxShadow: '0 1px 3px rgba(0,0,0,0.08)', border: '2px solid #FFF8E6',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                    <span style={{ fontSize: 20 }}>👁️</span>
                    <h4 style={{ fontSize: 14, fontWeight: 700, color: '#944F01' }}>Homoglyph / Typosquat</h4>
                  </div>
                  <div style={{ fontSize: 12, color: '#3D4F58', lineHeight: 1.6 }}>
                    {rec.homoglyphAnalysis.homoglyphSignals?.map((s, i) => (
                      <div key={i} style={{ marginBottom: 4 }}>• {s}</div>
                    ))}
                  </div>
                  {rec.homoglyphAnalysis.targetDomain && (
                    <div style={{ marginTop: 10, padding: '6px 12px', borderRadius: 8, background: '#FFF8E6', fontSize: 12 }}>
                      Target: <strong>{rec.homoglyphAnalysis.targetDomain}</strong> · Similarity: <strong>{(rec.homoglyphAnalysis.visualSimilarity * 100).toFixed(0)}%</strong>
                    </div>
                  )}
                </div>
              )}

              {rec.structuralAnalysis?.bypassTechniques?.length > 0 && (
                <div style={{
                  background: '#fff', borderRadius: 12, padding: 20,
                  boxShadow: '0 1px 3px rgba(0,0,0,0.08)', border: '2px solid #FFEAE5',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                    <span style={{ fontSize: 20 }}>🛡️</span>
                    <h4 style={{ fontSize: 14, fontWeight: 700, color: '#CF4A22' }}>Bypass Techniques Detected</h4>
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
                    {rec.structuralAnalysis.bypassTechniques.map((t, i) => (
                      <span key={i} style={{
                        padding: '3px 10px', borderRadius: 12,
                        background: '#FFEAE5', color: '#CF4A22',
                        fontSize: 11, fontWeight: 600,
                      }}>
                        {t.replace(/_/g, ' ').toUpperCase()}
                      </span>
                    ))}
                  </div>
                  <div style={{ fontSize: 12, color: '#3D4F58', lineHeight: 1.6 }}>
                    {rec.structuralAnalysis.structuralSignals?.map((s, i) => (
                      <div key={i} style={{ marginBottom: 4 }}>• {s}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Matched Documents — full evidence per criteria */}
          <MatchedEvidence
            similarThreats={result.similarThreats}
            threatIntelMatches={result.threatIntelMatches}
          />

          {/* Threat Relationship Graph */}
          <ThreatGraph url={result.urlRecord?.url} />
        </>
      )}
    </div>
  );
}
