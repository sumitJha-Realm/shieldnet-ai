'use client';

const card = {
  background: '#fff',
  borderRadius: 14,
  padding: 24,
  boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
  border: '1px solid #E8EDEB',
};

const badge = {
  display: 'inline-flex',
  alignItems: 'center',
  padding: '5px 10px',
  borderRadius: 999,
  fontSize: 11,
  fontWeight: 700,
};

export default function SummaryPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div
        style={{
          ...card,
          background: 'linear-gradient(135deg, #001E2B 0%, #023430 100%)',
          color: '#fff',
          border: 'none',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 24 }}>🧭</span>
          <h2 style={{ fontSize: 24, fontWeight: 800, margin: 0 }}>ShieldNet Solution Summary</h2>
        </div>
        <p style={{ fontSize: 14, lineHeight: 1.6, opacity: 0.95, margin: 0, maxWidth: 980 }}>
          This page explains the scope of the app, how to use each page, and important caveats for interpreting results.
          Use it as a quick orientation page for demos and stakeholder walkthroughs.
        </p>
      </div>

      <div style={card}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
          <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e' }}>Scope of this app</h3>
          <span style={{ ...badge, background: '#E8F4FD', color: '#12344D' }}>Validation Prototype</span>
        </div>
        <div style={{ display: 'grid', gap: 10, fontSize: 13, color: '#3D4F58', lineHeight: 1.55 }}>
          <div>
            <strong style={{ color: '#1a1c1e' }}>Primary objective:</strong> Validate malicious URL detection strategy using
            deterministic signals, semantic similarity search, and optional Foundry-backed agentic reasoning.
          </div>
          <div>
            <strong style={{ color: '#1a1c1e' }}>Core capabilities:</strong> URL scanning, threat evidence surfacing, campaign linking,
            Atlas text search, vector similarity search, and hybrid search comparison.
          </div>
          <div>
            <strong style={{ color: '#1a1c1e' }}>Intended use:</strong> Demo, solution architecture validation, workflow evaluation,
            and stakeholder communication.
          </div>
        </div>
      </div>

      <div style={{ ...card, border: '1px solid #F1C38B', background: '#FFF8EF' }}>
        <h3 style={{ marginTop: 0, marginBottom: 10, fontSize: 18, color: '#7D3600' }}>Important Result Disclaimer</h3>
        <div style={{ display: 'grid', gap: 10, fontSize: 13, color: '#5B3B1A', lineHeight: 1.55 }}>
          <div>
            <strong>Results are for strategy validation and demo purposes.</strong>
          </div>
          <div>
            Current backend data is limited in size and contains synthetic/demo-oriented records. It is not a complete production-grade threat corpus.
          </div>
          <div>
            Detection outcomes, risk scores, and campaign links may not be fully accurate for real-world internet-scale traffic.
          </div>
          <div>
            Do not treat this environment as an authoritative security decision system without production data hardening, calibration, and validation.
          </div>
        </div>
      </div>

      <div style={card}>
        <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 18, color: '#1a1c1e' }}>How to use the app (recommended flow)</h3>
        <div style={{ display: 'grid', gap: 10 }}>
          {[
            ['1. Dashboard', 'Start here to review system-level posture, trend direction, and recent activity snapshots.'],
            ['2. URL Scanner', 'Scan a specific URL, inspect risk score and evidence, and compare pipeline vs agentic output. For easier tracking, copy a URL from Threat Database and paste it here.'],
            ['3. Threat Database', 'Browse and filter stored URL records, shortlist by watched domains, and update review status. You can copy any URL and quickly re-check it in URL Scanner.'],
            ['4. Search Playground', 'Demonstrate Atlas text search, vector semantic search, and hybrid ranking behavior side by side.'],
            ['5. Architecture', 'Walk through technical design, scanner flow, and exact search/model features used in solution.'],
            ['6. Analytics', 'Review higher-level threat trends and chart-based summaries for communication.'],
            ['7. Settings', 'Check health, environment values display, and diagnostic controls.'],
          ].map(([title, detail]) => (
            <div key={title} style={{ background: '#F9FAFB', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px' }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1c1e', marginBottom: 4 }}>{title}</div>
              <div style={{ fontSize: 13, color: '#3D4F58', lineHeight: 1.5 }}>{detail}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={card}>
        <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 18, color: '#1a1c1e' }}>Page-wise information map</h3>
        <div style={{ display: 'grid', gap: 10 }}>
          {[
            ['Dashboard (/)', 'KPIs, recent events, and top-level threat trend visibility.'],
            ['Summary (/summary)', 'Scope, limitations, intended usage, and user navigation guidance.'],
            ['URL Scanner (/scan)', 'Single-URL analysis, evidence cards, classification, and campaign details when detected.'],
            ['Architecture (/architecture)', 'Pipeline/agentic flow diagrams and detailed technical stack/search features.'],
            ['Threat Database (/threats)', 'Queryable URL record repository with faceted filtering and operational triage actions.'],
            ['Search Playground (/search)', 'Controlled comparison of lexical, semantic, and hybrid retrieval behavior.'],
            ['Analytics (/analytics)', 'Chart-oriented aggregation views for reporting and demo storytelling.'],
            ['Settings (/settings)', 'Health checks, configuration visibility, and diagnostics/test controls.'],
          ].map(([page, info]) => (
            <div key={page} style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 12, background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13 }}>
              <div style={{ fontWeight: 700, color: '#3D4F58' }}>{page}</div>
              <div style={{ color: '#1a1c1e' }}>{info}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}