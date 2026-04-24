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

export default function ArchitecturePage() {
  const [activeView, setActiveView] = useState('pipeline');

  const viewTitle = useMemo(() => {
    if (activeView === 'agentic') return 'Multi-Agent Architecture';
    if (activeView === 'comparison') return 'Pipeline vs Multi-Agent Comparison';
    return 'Pipeline Mode Architecture';
  }, [activeView]);

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
    </div>
  );
}
