'use client';

import { useMemo, useState } from 'react';

const card = {
  background: '#fff',
  borderRadius: 14,
  padding: 24,
  boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
  border: '1px solid #E8EDEB',
};

const chip = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  padding: '6px 12px',
  borderRadius: 999,
  fontSize: 12,
  fontWeight: 700,
};

const stage = {
  padding: '10px 12px',
  borderRadius: 10,
  border: '1px solid #E8EDEB',
  background: '#F5F6F7',
  fontSize: 13,
  color: '#1a1c1e',
  lineHeight: 1.45,
};

function FlowStage({ index, title, description }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '28px 1fr', gap: 10, alignItems: 'start' }}>
      <div style={{
        width: 28,
        height: 28,
        borderRadius: 999,
        background: '#016BF8',
        color: '#fff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 12,
        fontWeight: 700,
      }}>
        {index}
      </div>
      <div style={stage}>
        <div style={{ fontWeight: 700, marginBottom: 4 }}>{title}</div>
        <div style={{ color: '#3D4F58' }}>{description}</div>
      </div>
    </div>
  );
}

function DiagramNode({ title, detail, color = '#016BF8', bg = '#E8F4FD' }) {
  return (
    <div style={{
      border: `1px solid ${color}33`,
      borderRadius: 12,
      padding: 12,
      background: bg,
      minHeight: 86,
    }}>
      <div style={{ fontSize: 12, fontWeight: 800, color: '#1a1c1e', marginBottom: 6 }}>{title}</div>
      <div style={{ fontSize: 12, color: '#3D4F58', lineHeight: 1.5 }}>{detail}</div>
    </div>
  );
}

function FeaturePill({ children, bg = '#E8F4FD', color = '#12344D' }) {
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding: '4px 10px',
      borderRadius: 999,
      fontSize: 11,
      fontWeight: 700,
      background: bg,
      color,
    }}>
      {children}
    </span>
  );
}

export default function ArchitecturePage() {
  const [activeView, setActiveView] = useState('pipeline');
  const [flowMode, setFlowMode] = useState('high');

  const viewTitle = useMemo(() => {
    if (activeView === 'agentic') return 'Multi-Agent Architecture';
    if (activeView === 'comparison') return 'Pipeline vs Multi-Agent Comparison';
    if (activeView === 'flow') return 'Scanner Flow Diagram';
    if (activeView === 'search-features') return 'Atlas Search + Vector Search Features';
    return 'Pipeline Mode Architecture';
  }, [activeView]);

  const flowNodes = useMemo(() => {
    if (flowMode === 'failure') {
      return [
        { title: 'Fail-Open: Embedding Error', detail: 'If embedding call fails, scanner continues with deterministic feature scoring and returns a usable result.', color: '#A70F2C', bg: '#FFEFF2' },
        { title: 'Fail-Open: Vector Search Error', detail: 'If Atlas vector search errors, threat similarity evidence is skipped, but risk engine still scores from URL signals.', color: '#A70F2C', bg: '#FFEFF2' },
        { title: 'Fail-Open: Campaign Error', detail: 'If campaign detection/update fails, URL scan still completes; only campaign tag is omitted.', color: '#A70F2C', bg: '#FFEFF2' },
        { title: 'Fail-Closed: Persistence Error', detail: 'If Mongo upsert fails, request fails because persisted result is required for scanner correctness.', color: '#7D3600', bg: '#FFF3E8' },
        { title: 'Fail-Closed: API Exception', detail: 'Unhandled runtime errors are surfaced as HTTP 500 from the scanner route.', color: '#7D3600', bg: '#FFF3E8' },
      ];
    }

    if (flowMode === 'detailed') {
      return [
        { title: '1. API Ingress', detail: 'FastAPI validates URL input and dispatches to scanner service.' },
        { title: '2. Waterfall Checks', detail: 'L1 memory cache, then L2 exact URL in MongoDB to avoid full recompute.', color: '#0F7B5A', bg: '#E3FCF7' },
        { title: '3. Feature Signals', detail: 'URL parsing + payload regex + DGA + homoglyph + structural bypass signals.', color: '#8A5A00', bg: '#FFF6E8' },
        { title: '4. Embedding', detail: 'Build summaryText and call Voyage embeddings API for query vector.', color: '#4B2B91', bg: '#F3EEFF' },
        { title: '5. Vector Retrieval', detail: 'Single Atlas vector query over urls collection (scan + threat_intel docs).' },
        { title: '6. Risk Engine', detail: 'Weighted scoring with thresholds and hard floors to produce classification/status.', color: '#0F7B5A', bg: '#E3FCF7' },
        { title: '7. Campaign Logic', detail: 'Consensus + category clustering + active window lookup/update in campaigns.', color: '#8A5A00', bg: '#FFF6E8' },
        { title: '8. Campaign Re-embed', detail: 'Rewrite summaryText with campaign context; update embedding for future one-query precision.', color: '#4B2B91', bg: '#F3EEFF' },
        { title: '9. Persist + Respond', detail: 'Store url record and return risk, evidence, recommended action, and campaign block.' },
      ];
    }

    return [
      { title: 'Receive', detail: 'Request enters scanner API and is validated.' },
      { title: 'Analyze', detail: 'Features + vector similarity + risk score are computed.' },
      { title: 'Decide', detail: 'Status and threat classification are generated.' },
      { title: 'Campaign Link', detail: 'URL is associated to active campaign when cluster evidence exists.' },
      { title: 'Respond', detail: 'Result is persisted and sent back with evidence.' },
    ];
  }, [flowMode]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{
        ...card,
        background: 'linear-gradient(135deg, #001E2B 0%, #023430 100%)',
        color: '#fff',
        border: 'none',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <span style={{ fontSize: 24 }}>🏗️</span>
          <h2 style={{ fontSize: 24, fontWeight: 800, margin: 0 }}>ShieldNet Architecture Views</h2>
        </div>
        <div style={{ fontSize: 14, lineHeight: 1.6, opacity: 0.95, maxWidth: 960 }}>
          This page shows both analysis architectures used by the scanner: Pipeline mode for deterministic scoring, and Multi-Agent mode where a 3-agent chain (Triage → Classifier → Action) powered by Microsoft Foundry reasons over pipeline evidence.
        </div>
      </div>

      <div style={card}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
          {[
            { key: 'pipeline', label: 'Pipeline Architecture' },
            { key: 'agentic', label: 'Multi-Agent Architecture' },
            { key: 'comparison', label: 'Compare Both' },
            { key: 'flow', label: 'Scanner Flow Diagram' },
            { key: 'search-features', label: 'Search Features Used' },
          ].map((item) => {
            const active = activeView === item.key;
            return (
              <button
                key={item.key}
                onClick={() => setActiveView(item.key)}
                style={{
                  border: 'none',
                  padding: '10px 16px',
                  borderRadius: 999,
                  fontSize: 13,
                  fontWeight: 700,
                  cursor: 'pointer',
                  background: active ? '#001E2B' : '#F5F6F7',
                  color: active ? '#fff' : '#3D4F58',
                }}
              >
                {item.label}
              </button>
            );
          })}
        </div>
        <div style={{ marginTop: 12, fontSize: 13, color: '#5C6C75' }}>
          Active view: <strong style={{ color: '#1a1c1e' }}>{viewTitle}</strong>
        </div>
      </div>

      {activeView === 'pipeline' && (
        <div style={card}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 14 }}>
            <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e' }}>Pipeline Mode</h3>
            <span style={{ ...chip, background: '#E8EDEB', color: '#1a1c1e' }}>Deterministic</span>
          </div>
          <p style={{ fontSize: 13, color: '#5C6C75', lineHeight: 1.6, marginTop: 0, marginBottom: 16 }}>
            Fast, rule-based scoring with fixed thresholds. Best for consistent decisions and predictable behavior.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <FlowStage index={1} title="URL Input" description="User submits URL from scanner page." />
            <FlowStage index={2} title="Waterfall Retrieval" description="L1 memory cache, then L2 MongoDB exact URL lookup, else continue to full analysis." />
            <FlowStage index={3} title="Feature Extraction" description="DNS, domain age, entropy, structural bypass, DGA and homoglyph indicators." />
            <FlowStage index={4} title="Vector + Intel Match" description="Find similar threats and threat-intel references for supporting evidence." />
            <FlowStage index={5} title="Risk Engine" description="Weighted score + hard floors + block/review thresholds determine status." />
            <FlowStage index={6} title="Result Output" description="Return classification, score breakdown, recommended action and evidence cards." />
          </div>
        </div>
      )}

      {activeView === 'agentic' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 14 }}>
              <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e' }}>Agentic Mode</h3>
              <span style={{ ...chip, background: '#E3FCF7', color: '#00684A' }}>Pipeline + Single Agent</span>
            </div>
            <p style={{ fontSize: 13, color: '#5C6C75', lineHeight: 1.6, marginTop: 0, marginBottom: 16 }}>
              Runs the deterministic pipeline first, then passes evidence through one Foundry agent for a faster explainable second opinion.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <FlowStage index={1} title="URL Input" description="User selects Pipeline + Foundry mode and submits URL." />
              <FlowStage index={2} title="Pipeline Baseline" description="Execute full deterministic pipeline (DNS, DGA, payload, structural, vector search) to create baseline score and status." />
              <FlowStage index={3} title="Evidence Packaging" description="Build compact context bundle: top 6 risk contributors, payload types, DGA, brand impersonation, structural signals, similar threat count and intel matches." />
            </div>

            <div style={{ margin: '18px 0 4px', fontWeight: 700, fontSize: 14, color: '#1a1c1e', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 18 }}>🤖</span> Foundry Agent
              <span style={{ fontSize: 11, fontWeight: 600, color: '#5C6C75', marginLeft: 4 }}>Single Step</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
              {[
                {
                  id: 'classifier',
                  role: 'Classification Agent',
                  color: '#016BF8',
                  bg: '#E8F4FD',
                  desc: 'Produces a threat decision label and bounded score adjustment (-15 to +15) using full pipeline evidence context.',
                },
              ].map((agent, i) => (
                <div key={agent.id} style={{ background: agent.bg, border: `1px solid ${agent.color}33`, borderRadius: 12, padding: 16, position: 'relative' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <span style={{ width: 24, height: 24, borderRadius: 999, background: agent.color, color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 800 }}>{i + 1}</span>
                    <span style={{ fontWeight: 700, fontSize: 13, color: '#1a1c1e' }}>{agent.role}</span>
                  </div>
                  <div style={{ fontSize: 12, color: '#3D4F58', lineHeight: 1.5 }}>{agent.desc}</div>
                  <div style={{ marginTop: 8, fontSize: 11, color: '#5C6C75' }}>
                    <strong>Output:</strong> decision, confidence (0-1), scoreAdjustment, signals, reasoning, actions
                  </div>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '12px 0 0', padding: '8px 12px', background: '#F5F6F7', borderRadius: 8, fontSize: 12, color: '#3D4F58' }}>
              <span style={{ fontSize: 16 }}>→</span>
              Single-agent mode trades some consensus depth for lower latency and simpler operation.
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 14 }}>
              <FlowStage index={4} title="Normalization" description="Clamp score adjustment (-15 to +15), derive agentic score/status, and package confidence and reasoning." />
              <FlowStage index={5} title="Diff Presentation" description="Show Pipeline vs Agentic deltas, decisive signals, reasoning steps, and recommended actions." />
            </div>
          </div>

          <div style={card}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#5C6C75', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.4px' }}>
              Runtime Reliability Notes
            </div>
            <div style={{ display: 'grid', gap: 8, fontSize: 13, color: '#1a1c1e' }}>
              <div><strong>Agent chain:</strong> Configurable via <code>AGENTIC_AGENT_CHAIN</code> env var (default: classifier). Custom prompts via <code>AGENTIC_AGENT_PROMPTS_JSON</code>.</div>
              <div><strong>Model:</strong> Microsoft Foundry endpoint using <code>gpt-5.4</code> with temperature 0.2 and JSON response format for structured outputs.</div>
              <div><strong>Client timeout:</strong> 90s safety timeout; single-agent runs should usually complete faster than previous multi-agent mode.</div>
              <div><strong>Failure handling:</strong> If Foundry is unavailable, scanner returns full deterministic pipeline output and surfaces a &quot;Foundry unavailable&quot; panel.</div>
              <div><strong>Debug path:</strong> Validate with <code>/api/v1/scan/agentic</code> and inspect backend logs for Foundry call failures.</div>
            </div>
          </div>
        </div>
      )}

      {activeView === 'comparison' && (
        <div style={card}>
          <h3 style={{ marginTop: 0, marginBottom: 14, fontSize: 17, color: '#1a1c1e' }}>Architecture Comparison</h3>
          <div style={{ display: 'grid', gap: 10 }}>
            {[
              ['Decision style', 'Fixed weighted thresholds', 'Single Foundry-agent decision with bounded score adjustment'],
              ['Agent count', 'None (deterministic)', '1 agent (classifier)'],
              ['Latency profile', 'Lower and predictable', 'Higher than pipeline, lower than prior 3-agent chain'],
              ['Explainability', 'Formula + rule evidence', 'Agent reasoning steps + decisive signals'],
              ['Failure behavior', 'Always available if backend up', 'Pipeline result returned; Foundry-unavailable state surfaced in UI'],
              ['Request timeout', '30s client timeout', '90s client timeout safety window'],
              ['Score adjustment', 'N/A (formula only)', 'Single Foundry agent applies -15 to +15 adjustment to pipeline baseline'],
              ['Best use', 'Strict policy enforcement', 'Analyst assist, second-opinion, and explainable verdicts'],
            ].map(([k, p, a]) => (
              <div
                key={k}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '180px 1fr 1fr',
                  gap: 12,
                  background: '#F5F6F7',
                  border: '1px solid #E8EDEB',
                  borderRadius: 10,
                  padding: '10px 12px',
                  fontSize: 13,
                }}
              >
                <div style={{ fontWeight: 700, color: '#3D4F58' }}>{k}</div>
                <div style={{ color: '#1a1c1e' }}>{p}</div>
                <div style={{ color: '#1a1c1e' }}>{a}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeView === 'flow' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e' }}>URL Scanner Technical Flow</h3>
              <span style={{ ...chip, background: '#E8F4FD', color: '#0A4B9F' }}>Pipeline + Campaign Layer</span>
            </div>
            <p style={{ fontSize: 13, color: '#5C6C75', lineHeight: 1.6, marginTop: 0, marginBottom: 14 }}>
              One request, one scanning pipeline. Waterfall checks reduce latency, vector search finds semantic matches,
              and campaign logic enriches the final URL embedding so future lookups use a single vector query.
            </p>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 14 }}>
              {[
                { key: 'high', label: 'High-level flow' },
                { key: 'detailed', label: 'Detailed component flow' },
                { key: 'failure', label: 'Failure-path overlay' },
              ].map((item) => {
                const active = flowMode === item.key;
                return (
                  <button
                    key={item.key}
                    onClick={() => setFlowMode(item.key)}
                    style={{
                      border: 'none',
                      padding: '8px 12px',
                      borderRadius: 999,
                      fontSize: 12,
                      fontWeight: 700,
                      cursor: 'pointer',
                      background: active ? '#001E2B' : '#F5F6F7',
                      color: active ? '#fff' : '#3D4F58',
                    }}
                  >
                    {item.label}
                  </button>
                );
              })}
            </div>

            <div style={{
              border: '1px solid #E8EDEB',
              borderRadius: 12,
              background: 'linear-gradient(180deg, #FBFDFD 0%, #F5F8F8 100%)',
              padding: 12,
              overflowX: 'auto',
            }}>
              <svg viewBox="0 0 1120 420" width="100%" role="img" aria-label="URL scanner architecture flow diagram" style={{ minWidth: 860 }}>
                <defs>
                  <marker id="arrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                    <polygon points="0 0, 10 3.5, 0 7" fill="#3D4F58" />
                  </marker>
                </defs>

                <rect x="20" y="30" rx="12" ry="12" width="130" height="52" fill="#E8F4FD" stroke="#98C4F5" />
                <text x="85" y="61" textAnchor="middle" fontSize="12" fontWeight="700" fill="#12344D">URL Input API</text>

                <rect x="210" y="20" rx="12" ry="12" width="170" height="72" fill="#E3FCF7" stroke="#A2E8DA" />
                <text x="295" y="46" textAnchor="middle" fontSize="12" fontWeight="700" fill="#0F5132">L1 Memory Cache</text>
                {flowMode !== 'high' && <text x="295" y="64" textAnchor="middle" fontSize="11" fill="#185F4A">Hit: sub-ms return</text>}

                <rect x="420" y="20" rx="12" ry="12" width="180" height="72" fill="#FFF6E8" stroke="#F0D6A2" />
                <text x="510" y="46" textAnchor="middle" fontSize="12" fontWeight="700" fill="#6B4E13">L2 Mongo URL Lookup</text>
                {flowMode !== 'high' && <text x="510" y="64" textAnchor="middle" fontSize="11" fill="#6B4E13">Reuse existing embedding</text>}

                <rect x="650" y="20" rx="12" ry="12" width="190" height="72" fill="#F3EEFF" stroke="#CDBAF6" />
                <text x="745" y="46" textAnchor="middle" fontSize="12" fontWeight="700" fill="#4B2B91">L3 Full Analysis</text>
                {flowMode !== 'high' && <text x="745" y="64" textAnchor="middle" fontSize="11" fill="#4B2B91">Extract → Embed → Search</text>}

                <line x1="150" y1="56" x2="210" y2="56" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />
                <line x1="380" y1="56" x2="420" y2="56" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />
                <line x1="600" y1="56" x2="650" y2="56" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />

                <rect x="70" y="150" rx="12" ry="12" width="230" height="72" fill="#E8F4FD" stroke="#98C4F5" />
                <text x="185" y="176" textAnchor="middle" fontSize="12" fontWeight="700" fill="#12344D">Feature Extraction</text>
                {flowMode !== 'high' && <text x="185" y="194" textAnchor="middle" fontSize="11" fill="#12344D">DGA, homoglyph, payload, structure</text>}

                <rect x="340" y="150" rx="12" ry="12" width="190" height="72" fill="#E3FCF7" stroke="#A2E8DA" />
                <text x="435" y="176" textAnchor="middle" fontSize="12" fontWeight="700" fill="#0F5132">Embedding Service</text>
                {flowMode !== 'high' && <text x="435" y="194" textAnchor="middle" fontSize="11" fill="#185F4A">Voyage model vector</text>}

                <rect x="570" y="150" rx="12" ry="12" width="210" height="72" fill="#FFF6E8" stroke="#F0D6A2" />
                <text x="675" y="176" textAnchor="middle" fontSize="12" fontWeight="700" fill="#6B4E13">Atlas Vector Search</text>
                {flowMode !== 'high' && <text x="675" y="194" textAnchor="middle" fontSize="11" fill="#6B4E13">scan + threat_intel neighbors</text>}

                <rect x="820" y="150" rx="12" ry="12" width="220" height="72" fill="#F3EEFF" stroke="#CDBAF6" />
                <text x="930" y="176" textAnchor="middle" fontSize="12" fontWeight="700" fill="#4B2B91">Risk Engine + Classification</text>
                {flowMode !== 'high' && <text x="930" y="194" textAnchor="middle" fontSize="11" fill="#4B2B91">weights + hard floors + thresholds</text>}

                <line x1="300" y1="186" x2="340" y2="186" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />
                <line x1="530" y1="186" x2="570" y2="186" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />
                <line x1="780" y1="186" x2="820" y2="186" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />

                <rect x="90" y="292" rx="12" ry="12" width="220" height="86" fill="#EAFBF2" stroke="#9DDFC1" />
                <text x="200" y="322" textAnchor="middle" fontSize="12" fontWeight="700" fill="#1C6A43">Campaign Detection</text>
                {flowMode !== 'high' && <text x="200" y="340" textAnchor="middle" fontSize="11" fill="#1C6A43">neighbor vote + category cluster</text>}
                {flowMode !== 'high' && <text x="200" y="356" textAnchor="middle" fontSize="11" fill="#1C6A43">active-window check</text>}

                <rect x="350" y="292" rx="12" ry="12" width="220" height="86" fill="#E8F4FD" stroke="#98C4F5" />
                <text x="460" y="322" textAnchor="middle" fontSize="12" fontWeight="700" fill="#12344D">Campaign Collection</text>
                {flowMode !== 'high' && <text x="460" y="340" textAnchor="middle" fontSize="11" fill="#12344D">update aggregates</text>}
                {flowMode !== 'high' && <text x="460" y="356" textAnchor="middle" fontSize="11" fill="#12344D">urlCount, avgRisk, lastSeen</text>}

                <rect x="610" y="292" rx="12" ry="12" width="240" height="86" fill="#FFF6E8" stroke="#F0D6A2" />
                <text x="730" y="322" textAnchor="middle" fontSize="12" fontWeight="700" fill="#6B4E13">Campaign-Enriched Re-embed</text>
                {flowMode !== 'high' && <text x="730" y="340" textAnchor="middle" fontSize="11" fill="#6B4E13">summaryText + campaign context</text>}
                {flowMode !== 'high' && <text x="730" y="356" textAnchor="middle" fontSize="11" fill="#6B4E13">single-query future lookups</text>}

                <rect x="890" y="292" rx="12" ry="12" width="190" height="86" fill="#F3EEFF" stroke="#CDBAF6" />
                <text x="985" y="322" textAnchor="middle" fontSize="12" fontWeight="700" fill="#4B2B91">Store + Return</text>
                {flowMode !== 'high' && <text x="985" y="340" textAnchor="middle" fontSize="11" fill="#4B2B91">urls upsert + response</text>}
                {flowMode !== 'high' && <text x="985" y="356" textAnchor="middle" fontSize="11" fill="#4B2B91">risk, evidence, campaign</text>}

                <line x1="930" y1="222" x2="930" y2="276" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />
                <line x1="930" y1="276" x2="200" y2="276" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />
                <line x1="310" y1="335" x2="350" y2="335" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />
                <line x1="570" y1="335" x2="610" y2="335" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />
                <line x1="850" y1="335" x2="890" y2="335" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#arrow)" />

                {flowMode === 'failure' && (
                  <g>
                    <line x1="435" y1="222" x2="435" y2="264" stroke="#A70F2C" strokeWidth="2.5" strokeDasharray="6 5" markerEnd="url(#arrow)" />
                    <line x1="675" y1="222" x2="675" y2="264" stroke="#A70F2C" strokeWidth="2.5" strokeDasharray="6 5" markerEnd="url(#arrow)" />
                    <line x1="200" y1="378" x2="200" y2="402" stroke="#A70F2C" strokeWidth="2.5" strokeDasharray="6 5" markerEnd="url(#arrow)" />

                    <rect x="360" y="378" rx="8" ry="8" width="150" height="26" fill="#FFEFF2" stroke="#E38CA1" />
                    <text x="435" y="395" textAnchor="middle" fontSize="10" fontWeight="700" fill="#A70F2C">embed fail → deterministic path</text>

                    <rect x="595" y="378" rx="8" ry="8" width="160" height="26" fill="#FFEFF2" stroke="#E38CA1" />
                    <text x="675" y="395" textAnchor="middle" fontSize="10" fontWeight="700" fill="#A70F2C">search fail → keep scoring</text>

                    <rect x="118" y="404" rx="8" ry="8" width="164" height="26" fill="#FFEFF2" stroke="#E38CA1" />
                    <text x="200" y="421" textAnchor="middle" fontSize="10" fontWeight="700" fill="#A70F2C">campaign fail → no tag, return</text>
                  </g>
                )}
              </svg>
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 16, color: '#1a1c1e' }}>
              {flowMode === 'failure' ? 'Failure Behavior Map' : 'Step-by-Step Engineering Map'}
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10 }}>
              {flowNodes.map((node) => (
                <DiagramNode
                  key={node.title}
                  title={node.title}
                  detail={node.detail}
                  color={node.color}
                  bg={node.bg}
                />
              ))}
            </div>
          </div>
        </div>
      )}

      {activeView === 'search-features' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e' }}>Exact Search Features Used In This Solution</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <FeaturePill>Atlas Search</FeaturePill>
                <FeaturePill bg="#F3EEFF" color="#4B2B91">Vector Search</FeaturePill>
                <FeaturePill bg="#E3FCF7" color="#0F5132">Hybrid / Rank Fusion</FeaturePill>
              </div>
            </div>

            <p style={{ fontSize: 13, color: '#5C6C75', lineHeight: 1.6, marginTop: 0, marginBottom: 16 }}>
              This tab explains the exact MongoDB search capabilities already used in the codebase and how each one improves URL scanner quality, explainability, and demo value.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
              <div style={{ border: '1px solid #E8EDEB', borderRadius: 14, padding: 18, background: '#FBFDFF' }}>
                <div style={{ fontSize: 15, fontWeight: 800, color: '#1a1c1e', marginBottom: 10 }}>Atlas Search features used here</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13, color: '#3D4F58' }}>
                  <div>
                    <strong>1. Multi-field full-text search</strong><br />
                    Query is executed on <strong>url</strong>, <strong>domain</strong>, and <strong>summaryText</strong> so analysts can search raw URLs, domain fragments, or narrative threat context.
                  </div>
                  <div>
                    <strong>2. Fuzzy matching</strong><br />
                    Configured with <strong>maxEdits=2</strong> and <strong>prefixLength=2</strong> to catch typo-style searches such as “phising” or malformed domain patterns during demos and investigations.
                  </div>
                  <div>
                    <strong>3. Highlight support</strong><br />
                    Highlights are requested for matched fields, enabling future UI emphasis on why a lexical match happened.
                  </div>
                  <div>
                    <strong>4. Structured filters</strong><br />
                    Search can be filtered by <strong>docType</strong>, <strong>threatClassification</strong>, <strong>attackCategory</strong>, <strong>status</strong>, <strong>dnsStatus</strong>, and <strong>riskScore range</strong>.
                  </div>
                  <div>
                    <strong>5. Faceting</strong><br />
                    Facets are implemented for <strong>threatClassification</strong>, <strong>dnsStatus</strong>, and <strong>status</strong> to support analyst exploration and drill-down.
                  </div>
                  <div>
                    <strong>6. Shared index</strong><br />
                    Uses <strong>url_search_index</strong> over the unified <strong>urls</strong> collection, covering both scanned URLs and threat-intel style documents.
                  </div>
                </div>
              </div>

              <div style={{ border: '1px solid #E8EDEB', borderRadius: 14, padding: 18, background: '#FCFAFF' }}>
                <div style={{ fontSize: 15, fontWeight: 800, color: '#1a1c1e', marginBottom: 10 }}>Vector Search features used here</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13, color: '#3D4F58' }}>
                  <div>
                    <strong>1. Semantic embedding search</strong><br />
                    Query text is embedded first, then compared against the stored <strong>embedding</strong> field to find semantically related threats even when exact keywords differ.
                  </div>
                  <div>
                    <strong>2. Cosine similarity index</strong><br />
                    Uses <strong>url_vector_index</strong> with a <strong>1024-dim</strong> vector definition and <strong>cosine</strong> similarity for nearest-neighbour retrieval.
                  </div>
                  <div>
                    <strong>3. ANN candidate expansion</strong><br />
                    Search runs with <strong>numCandidates=100</strong> before returning top-k results, improving recall for semantically similar malicious URLs.
                  </div>
                  <div>
                    <strong>4. Metadata filtering</strong><br />
                    Vector queries can be filtered by <strong>threatClassification</strong>, <strong>status</strong>, and campaign-related metadata already present in the index definition.
                  </div>
                  <div>
                    <strong>5. Unified threat retrieval</strong><br />
                    The same vector search reads from one <strong>urls</strong> collection containing both regular scan records and threat-intel records, reducing extra query hops.
                  </div>
                  <div>
                    <strong>6. Campaign-aware re-embedding</strong><br />
                    After campaign detection, summary text is rewritten with campaign context and re-embedded so future vector retrieval becomes more precise.
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 14, fontSize: 17, color: '#1a1c1e' }}>How these features enhance URL scanner functionality</h3>
            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['Catch misspellings and operator typos', 'Atlas fuzzy search helps analysts find phishing-like URLs and intel even when the search input is imperfect.'],
                ['Find semantically similar threats', 'Vector search surfaces lookalike malicious URLs that do not share exact words but behave like the same attack family.'],
                ['Improve explanation quality', 'Atlas lexical hits and vector neighbours become concrete evidence blocks in the scanner response, making verdicts easier to justify.'],
                ['Support campaign clustering', 'Vector neighbour similarity feeds campaign detection, allowing one suspicious URL to be tied to a broader coordinated attack.'],
                ['Reduce false negatives', 'If exact keyword matching misses a new lure page, semantic retrieval can still catch it through similar structure and threat language.'],
                ['Enable shortlist and triage workflows', 'Atlas filtering and faceting let analysts narrow results by status, DNS condition, risk band, and threat category.'],
                ['Speed up future lookups', 'Campaign-enriched embeddings mean future scans need only one vector search to recover both similarity and campaign context.'],
                ['Strengthen demos for stakeholders', 'You can clearly show lexical search, semantic search, and hybrid/rank-fusion as separate capabilities instead of a single black-box search box.'],
              ].map(([title, detail]) => (
                <div
                  key={title}
                  style={{
                    background: '#F5F6F7',
                    border: '1px solid #E8EDEB',
                    borderRadius: 10,
                    padding: '12px 14px',
                  }}
                >
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1c1e', marginBottom: 4 }}>{title}</div>
                  <div style={{ fontSize: 13, color: '#3D4F58', lineHeight: 1.5 }}>{detail}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 14, fontSize: 17, color: '#1a1c1e' }}>Feature-to-Code Mapping</h3>
            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['Atlas text + fuzzy search', 'backend/services/search/atlas_search_service.py'],
                ['Atlas facets', 'backend/services/search/atlas_search_service.py'],
                ['Vector query embedding + ANN retrieval', 'backend/services/search/vector_search_service.py'],
                ['Hybrid rank fusion', 'backend/services/search/hybrid_search_service.py'],
                ['Scanner vector evidence + atlas lexical enrichment', 'backend/services/url_analysis_service.py'],
                ['Demo scenarios for Atlas/Vector/Hybrid', 'backend/services/search/unified_search_service.py'],
              ].map(([feature, file]) => (
                <div key={feature} style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 12, background: '#F9FAFB', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13 }}>
                  <div style={{ fontWeight: 700, color: '#3D4F58' }}>{feature}</div>
                  <div style={{ color: '#1a1c1e', fontFamily: 'monospace' }}>{file}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
