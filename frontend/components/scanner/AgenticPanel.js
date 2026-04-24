'use client';

const STATUS_COLORS = {
  blocked: { bg: '#FFEAE5', color: '#CF4A22' },
  under_review: { bg: '#FFF8E6', color: '#944F01' },
  allowed: { bg: '#E3FCF7', color: '#00684A' },
};

function ComparisonRow({ label, pipelineValue, agenticValue, deltaLabel, highlight = false }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '140px minmax(0, 1fr) minmax(0, 1fr) 90px',
        gap: 12,
        alignItems: 'center',
        padding: '12px 14px',
        borderRadius: 10,
        background: highlight ? '#F8FBF8' : '#F5F6F7',
        border: `1px solid ${highlight ? '#DCE9E1' : '#E8EDEB'}`,
      }}
    >
      <div style={{ fontSize: 12, fontWeight: 700, color: '#5C6C75', textTransform: 'uppercase', letterSpacing: '0.3px' }}>
        {label}
      </div>
      <div style={{ fontSize: 13, color: '#1A1C1E', fontWeight: 600 }}>{pipelineValue}</div>
      <div style={{ fontSize: 13, color: '#1A1C1E', fontWeight: 700 }}>{agenticValue}</div>
      <div style={{ fontSize: 12, color: highlight ? '#00684A' : '#5C6C75', fontWeight: 700, textAlign: 'right' }}>{deltaLabel}</div>
    </div>
  );
}

function ListSection({ title, items }) {
  if (!items?.length) {
    return null;
  }

  return (
    <div>
      <div style={{ fontSize: 11, fontWeight: 700, color: '#5C6C75', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.4px' }}>
        {title}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {items.map((item, index) => (
          <div
            key={`${title}-${index}`}
            style={{
              padding: '10px 12px',
              borderRadius: 8,
              background: '#F5F6F7',
              border: '1px solid #E8EDEB',
              fontSize: 13,
              lineHeight: 1.5,
              color: '#1A1C1E',
            }}
          >
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}

function WorkflowSteps({ steps, workflowType }) {
  if (!steps?.length) {
    return null;
  }

  const workflowLabel = workflowType === 'single-agent' ? 'Single-Agent Workflow' : 'Multi-Agent Workflow';

  return (
    <div>
      <div style={{ fontSize: 11, fontWeight: 700, color: '#5C6C75', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.4px' }}>
        {workflowLabel}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {steps.map((step, index) => (
          <div
            key={`${step.agentId}-${index}`}
            style={{
              border: '1px solid #E8EDEB',
              borderRadius: 10,
              padding: '12px 14px',
              background: '#F5F6F7',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#1A1C1E' }}>
                {index + 1}. {step.role || step.agentId}
              </div>
              <div style={{ fontSize: 11, color: '#5C6C75', fontWeight: 700 }}>
                {Math.round((step.confidence || 0) * 100)}% confidence
              </div>
            </div>
            <div style={{ fontSize: 12, color: '#3D4F58' }}>
              Decision: <strong style={{ color: '#1A1C1E' }}>{step.decision || 'undetermined'}</strong>
              {' · '}Adjustment: <strong style={{ color: '#1A1C1E' }}>{step.scoreAdjustment > 0 ? `+${step.scoreAdjustment}` : `${step.scoreAdjustment || 0}`}</strong>
            </div>
            {step.reasoning?.length > 0 && (
              <div style={{ fontSize: 12, color: '#1A1C1E', lineHeight: 1.5 }}>
                {step.reasoning[0]}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AgenticPanel({ pipelineScore, pipelineStatus, agenticAnalysis }) {
  if (!agenticAnalysis) {
    return null;
  }

  if (!agenticAnalysis.available) {
    return (
      <div style={{ background: '#fff', borderRadius: 12, padding: 24, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 12 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#1A1C1E', margin: 0 }}>Agentic Reasoning</h3>
          <span style={{ padding: '4px 10px', borderRadius: 999, background: '#F5F6F7', color: '#5C6C75', fontSize: 11, fontWeight: 700 }}>
            Foundry unavailable
          </span>
        </div>
        <div style={{ fontSize: 13, color: '#5C6C75', lineHeight: 1.6 }}>
          {agenticAnalysis.error || 'No Foundry response was returned.'}
        </div>
      </div>
    );
  }

  const statusStyle = STATUS_COLORS[agenticAnalysis.agenticStatus] || STATUS_COLORS.allowed;
  const delta = agenticAnalysis.scoreAdjustment || 0;
  const deltaLabel = delta > 0 ? `+${delta}` : `${delta}`;
  const normalizedPipelineStatus = (pipelineStatus || 'unknown').replace('_', ' ');
  const normalizedAgenticStatus = (agenticAnalysis.agenticStatus || 'unknown').replace('_', ' ');
  const statusChanged = pipelineStatus !== agenticAnalysis.agenticStatus;
  const verdictLabel = agenticAnalysis.verdict || 'No verdict';

  return (
    <div style={{ background: '#fff', borderRadius: 12, padding: 24, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, alignItems: 'flex-start' }}>
        <div>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#1A1C1E', margin: '0 0 6px' }}>Agentic Reasoning</h3>
          <div style={{ fontSize: 12, color: '#5C6C75' }}>
            Microsoft Foundry · {agenticAnalysis.model}
          </div>
        </div>
        <span style={{ padding: '4px 10px', borderRadius: 999, background: statusStyle.bg, color: statusStyle.color, fontSize: 11, fontWeight: 700 }}>
          {agenticAnalysis.agenticStatus.replace('_', ' ').toUpperCase()}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12 }}>
        <div style={{ padding: '14px 16px', borderRadius: 10, background: '#F5F6F7', border: '1px solid #E8EDEB' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#5C6C75', marginBottom: 6 }}>Pipeline Score</div>
          <div style={{ fontSize: 24, fontWeight: 800, color: '#1A1C1E' }}>{pipelineScore}</div>
          <div style={{ fontSize: 11, color: '#889397' }}>{pipelineStatus?.replace('_', ' ')}</div>
        </div>
        <div style={{ padding: '14px 16px', borderRadius: 10, background: '#F5F6F7', border: '1px solid #E8EDEB' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#5C6C75', marginBottom: 6 }}>Agentic Score</div>
          <div style={{ fontSize: 24, fontWeight: 800, color: '#1A1C1E' }}>{agenticAnalysis.agenticRiskScore}</div>
          <div style={{ fontSize: 11, color: '#889397' }}>Delta {deltaLabel}</div>
        </div>
        <div style={{ padding: '14px 16px', borderRadius: 10, background: '#F5F6F7', border: '1px solid #E8EDEB' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#5C6C75', marginBottom: 6 }}>Confidence</div>
          <div style={{ fontSize: 24, fontWeight: 800, color: '#1A1C1E' }}>{Math.round((agenticAnalysis.confidence || 0) * 100)}%</div>
          <div style={{ fontSize: 11, color: '#889397' }}>{agenticAnalysis.verdict}</div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#5C6C75', textTransform: 'uppercase', letterSpacing: '0.4px' }}>
            Pipeline vs Agentic
          </div>
          <span style={{
            padding: '4px 10px',
            borderRadius: 999,
            background: statusChanged ? '#FFF8E6' : '#E3FCF7',
            color: statusChanged ? '#944F01' : '#00684A',
            fontSize: 11,
            fontWeight: 700,
          }}>
            {statusChanged ? 'Status changed' : 'Status unchanged'}
          </span>
        </div>

        <div style={{ display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '140px minmax(0, 1fr) minmax(0, 1fr) 90px', gap: 12, padding: '0 14px' }}>
            <div />
            <div style={{ fontSize: 11, fontWeight: 700, color: '#889397', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Pipeline</div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#889397', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Agentic</div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#889397', textTransform: 'uppercase', letterSpacing: '0.4px', textAlign: 'right' }}>Delta</div>
          </div>

          <ComparisonRow
            label="Score"
            pipelineValue={`${pipelineScore}/100`}
            agenticValue={`${agenticAnalysis.agenticRiskScore}/100`}
            deltaLabel={deltaLabel}
            highlight={delta !== 0}
          />
          <ComparisonRow
            label="Status"
            pipelineValue={normalizedPipelineStatus}
            agenticValue={normalizedAgenticStatus}
            deltaLabel={statusChanged ? 'Changed' : 'Same'}
            highlight={statusChanged}
          />
          <ComparisonRow
            label="Verdict"
            pipelineValue={normalizedPipelineStatus}
            agenticValue={verdictLabel}
            deltaLabel={`${Math.round((agenticAnalysis.confidence || 0) * 100)}%`}
          />
        </div>
      </div>

      <div style={{ padding: '14px 16px', borderRadius: 10, background: '#F8FBF8', border: '1px solid #DCE9E1', color: '#1A1C1E', fontSize: 14, lineHeight: 1.6 }}>
        {agenticAnalysis.summary}
      </div>

      <ListSection title="Decisive Signals" items={agenticAnalysis.decisiveSignals} />
      <ListSection title="Reasoning Steps" items={agenticAnalysis.reasoningSteps} />
      <ListSection title="Recommended Actions" items={agenticAnalysis.recommendedActions} />
      <WorkflowSteps steps={agenticAnalysis.workflowSteps} workflowType={agenticAnalysis.workflowType} />
    </div>
  );
}