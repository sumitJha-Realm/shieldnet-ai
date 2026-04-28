'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { getUrlGraph } from '../../lib/api';

/* ── Colour palette ───────────────────────────────────────────────── */
const STATUS_COLORS = {
  blocked: '#CF4A22',
  under_review: '#F2A900',
  allowed: '#00684A',
  benign: '#00684A',
};
const DEGREE_RING = { 1: 130, 2: 260 };
const DEGREE_LABEL = { 0: 'Scanned URL', 1: '1st Degree', 2: '2nd Degree' };
const EDGE_COLOR = 'rgba(1, 107, 248, 0.25)';
const EDGE_STRONG = 'rgba(1, 107, 248, 0.55)';

/* ── Helpers ──────────────────────────────────────────────────────── */
function truncate(s, n = 28) {
  return s && s.length > n ? s.slice(0, n) + '…' : s;
}

function degreeBadge(d) {
  const bg = d === 1 ? '#E3FCF7' : d === 2 ? '#FFF3CD' : '#E8EDEB';
  const fg = d === 1 ? '#00684A' : d === 2 ? '#856404' : '#1a1c1e';
  return { background: bg, color: fg, fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10 };
}

/* ================================================================== */
export default function ThreatGraph({ url }) {
  const [graph, setGraph] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [hovered, setHovered] = useState(null);
  const [selected, setSelected] = useState(null);
  const [maxDepth, setMaxDepth] = useState(1);
  const svgRef = useRef(null);

  const fetchGraph = useCallback(async () => {
    if (!url) return;
    setLoading(true);
    setError(null);
    try {
      const res = await getUrlGraph(url, maxDepth);
      setGraph(res.data);
    } catch {
      setError('Could not load relationship graph');
    } finally {
      setLoading(false);
    }
  }, [url, maxDepth]);

  useEffect(() => { fetchGraph(); }, [fetchGraph]);

  if (!url) return null;

  /* ── Layout: assign positions (radial) ────────────────────────── */
  const layoutNodes = (graph) => {
    if (!graph?.nodes?.length) return { positioned: [], edgeLines: [] };

    const cx = 320, cy = 280;
    const nodeMap = {};

    // Assign degree to each node based on edges
    const degreeMap = {};
    degreeMap[url] = 0;
    for (const e of (graph.edges || [])) {
      if (e.from === url) degreeMap[e.to] = Math.min(degreeMap[e.to] ?? 99, e.degree || 1);
      if (e.to === url) degreeMap[e.from] = Math.min(degreeMap[e.from] ?? 99, e.degree || 1);
    }
    // Second pass for degree-2 nodes connected through degree-1
    for (const e of (graph.edges || [])) {
      if (degreeMap[e.from] === 1 && degreeMap[e.to] === undefined) degreeMap[e.to] = 2;
      if (degreeMap[e.to] === 1 && degreeMap[e.from] === undefined) degreeMap[e.from] = 2;
    }

    // Group by degree
    const groups = { 0: [], 1: [], 2: [] };
    for (const node of graph.nodes) {
      const deg = degreeMap[node.url] ?? 2;
      groups[Math.min(deg, 2)].push(node);
    }

    // Position nodes in rings
    const positioned = [];
    for (const [deg, nodes] of Object.entries(groups)) {
      const d = parseInt(deg);
      const radius = DEGREE_RING[d] || 0;
      nodes.forEach((node, i) => {
        const angle = (2 * Math.PI * i) / Math.max(nodes.length, 1) - Math.PI / 2;
        const x = d === 0 ? cx : cx + radius * Math.cos(angle);
        const y = d === 0 ? cy : cy + radius * Math.sin(angle);
        const p = { ...node, x, y, degree: d };
        positioned.push(p);
        nodeMap[node.url] = p;
      });
    }

    // Build edge lines with coordinates
    const edgeLines = (graph.edges || []).map(e => {
      const from = nodeMap[e.from];
      const to = nodeMap[e.to];
      if (!from || !to) return null;
      return { ...e, x1: from.x, y1: from.y, x2: to.x, y2: to.y };
    }).filter(Boolean);

    return { positioned, edgeLines };
  };

  const { positioned, edgeLines } = graph ? layoutNodes(graph) : { positioned: [], edgeLines: [] };
  const hasData = positioned.length > 1;

  const cardStyle = {
    background: '#fff', borderRadius: 12, padding: 24,
    boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
  };

  return (
    <div style={cardStyle}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h3 style={{ fontSize: 16, fontWeight: 600, margin: 0 }}>Threat Relationship Graph</h3>
          <p style={{ fontSize: 12, color: '#5C6C75', margin: '4px 0 0' }}>
            Shows how this URL relates to previously flagged URLs via MongoDB <code>$graphLookup</code>
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <label style={{ fontSize: 12, color: '#5C6C75' }}>Depth:</label>
          {[1, 2, 3].map(d => (
            <button
              key={d}
              onClick={() => setMaxDepth(d)}
              style={{
                padding: '4px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                border: '1px solid #E8EDEB', cursor: 'pointer',
                background: maxDepth === d ? '#016BF8' : '#fff',
                color: maxDepth === d ? '#fff' : '#1a1c1e',
              }}
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {loading && <div style={{ color: '#5C6C75', fontSize: 13, padding: 40, textAlign: 'center' }}>Loading graph...</div>}
      {error && <div style={{ color: '#CF4A22', fontSize: 13, padding: 20 }}>{error}</div>}

      {!loading && !error && !hasData && (
        <div style={{
          padding: 40, textAlign: 'center', color: '#5C6C75', fontSize: 13,
          border: '1px dashed #E8EDEB', borderRadius: 8,
        }}>
          No relationships found yet. Scan more URLs to build the graph.
        </div>
      )}

      {!loading && hasData && (
        <>
          {/* Legend */}
          <div style={{ display: 'flex', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
            {[0, 1, 2].map(d => (
              <span key={d} style={degreeBadge(d)}>{DEGREE_LABEL[d]}</span>
            ))}
            <span style={{ fontSize: 10, color: '#5C6C75', display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 12, height: 3, background: EDGE_STRONG, display: 'inline-block', borderRadius: 2 }} />
              Strong link (&gt;0.6)
            </span>
            <span style={{ fontSize: 10, color: '#5C6C75', display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 12, height: 3, background: EDGE_COLOR, display: 'inline-block', borderRadius: 2 }} />
              Weak link
            </span>
          </div>

          {/* SVG Graph */}
          <svg
            ref={svgRef}
            viewBox="0 0 640 560"
            style={{ width: '100%', maxHeight: 560, border: '1px solid #F5F6F7', borderRadius: 8, background: '#FAFBFC' }}
          >
            {/* Degree rings */}
            {[1, 2].map(d => (
              <circle
                key={d}
                cx={320} cy={280} r={DEGREE_RING[d]}
                fill="none" stroke="#E8EDEB" strokeWidth={1} strokeDasharray="4 4"
              />
            ))}
            {[1, 2].map(d => (
              <text
                key={`label-${d}`}
                x={320} y={280 - DEGREE_RING[d] - 6}
                textAnchor="middle" fontSize={10} fill="#5C6C75"
              >
                {DEGREE_LABEL[d]}
              </text>
            ))}

            {/* Edges */}
            {edgeLines.map((e, i) => (
              <line
                key={i}
                x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
                stroke={e.strength > 0.6 ? EDGE_STRONG : EDGE_COLOR}
                strokeWidth={Math.max(1, e.strength * 4)}
              />
            ))}

            {/* Edge strength labels */}
            {edgeLines.map((e, i) => (
              <text
                key={`es-${i}`}
                x={(e.x1 + e.x2) / 2}
                y={(e.y1 + e.y2) / 2 - 4}
                textAnchor="middle" fontSize={9} fill="#5C6C75"
              >
                {(e.strength * 100).toFixed(0)}%
              </text>
            ))}

            {/* Nodes */}
            {positioned.map((node) => {
              const isRoot = node.degree === 0;
              const r = isRoot ? 24 : 16;
              const fill = isRoot ? '#016BF8' : (STATUS_COLORS[node.status] || '#5C6C75');
              const isHov = hovered === node.url;
              const isSel = selected === node.url;

              return (
                <g
                  key={node.url}
                  onMouseEnter={() => setHovered(node.url)}
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => setSelected(prev => prev === node.url ? null : node.url)}
                  style={{ cursor: 'pointer' }}
                >
                  {/* Glow on hover or selected */}
                  {(isHov || isSel) && <circle cx={node.x} cy={node.y} r={r + 6} fill={fill} opacity={0.15} />}
                  <circle
                    cx={node.x} cy={node.y} r={r}
                    fill={fill} stroke="#fff" strokeWidth={2}
                  />
                  {isRoot && (
                    <text x={node.x} y={node.y + 4} textAnchor="middle" fontSize={10} fill="#fff" fontWeight={700}>★</text>
                  )}
                  {/* URL label below node */}
                  <text
                    x={node.x} y={node.y + r + 14}
                    textAnchor="middle" fontSize={10} fill="#1a1c1e"
                    fontWeight={isRoot ? 600 : 400}
                  >
                    {truncate(node.domain || node.url, 20)}
                  </text>
                  {/* Risk score badge */}
                  {node.riskScore != null && (
                    <text
                      x={node.x} y={node.y + r + 26}
                      textAnchor="middle" fontSize={9} fill={fill}
                    >
                      Risk: {node.riskScore}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>

          {/* Selected node detail panel + Stats wrapper */}
          <div style={{ position: 'relative' }}>
          {/* Detail panel — shown when a node is clicked */}
          {selected && (() => {
            const node = positioned.find(n => n.url === selected);
            const nodeEdges = edgeLines.filter(e => e.from === selected || e.to === selected);
            if (!node) return null;
            return (
              <div style={{
                marginTop: 12, padding: 14, background: '#1a1c1e', borderRadius: 8,
                color: '#E8EDEB', fontSize: 12, lineHeight: 1.7,
              }}>
                <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6 }}>
                  {node.url}
                </div>
                <div>
                  <span style={{ color: '#5C6C75' }}>Risk Score: </span>
                  <span style={{ color: STATUS_COLORS[node.status] || '#E8EDEB', fontWeight: 600 }}>
                    {node.riskScore ?? '—'}
                  </span>
                  <span style={{ color: '#5C6C75', marginLeft: 12 }}>Status: </span>
                  <span>{node.status || '—'}</span>
                  <span style={{ color: '#5C6C75', marginLeft: 12 }}>Classification: </span>
                  <span>{node.threatClassification || '—'}</span>
                </div>
                {nodeEdges.length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <span style={{ color: '#5C6C75' }}>Relationship factors:</span>
                    {nodeEdges.map((e, i) => (
                      <div key={i} style={{ marginLeft: 8, marginTop: 2 }}>
                        → {e.from === selected ? e.to : e.from}
                        <span style={{ color: '#00ED64', marginLeft: 6 }}>{(e.strength * 100).toFixed(0)}% strength</span>
                        {(e.factors || []).map((f, j) => (
                          <span key={j} style={{ color: '#5C6C75', marginLeft: 8 }}>
                            [{f.type}: {f.detail || `${(f.score * 100).toFixed(0)}%`}]
                          </span>
                        ))}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })()}

          {/* Stats */}
          <div style={{ display: 'flex', gap: 24, marginTop: 12, fontSize: 12, color: '#5C6C75' }}>
            <span>{positioned.length} nodes</span>
            <span>{edgeLines.length} edges</span>
            <span>Depth: {maxDepth}</span>
          </div>
          </div>
        </>
      )}
    </div>
  );
}
