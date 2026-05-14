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

const UC_TEST_CASES = [
  { uc: 'UC 1', name: 'Typosquatting', input: 'https://sbi-secure-login.com/verify', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Brand distance + phishing keywords + young-domain risk' },
  { uc: 'UC 2', name: 'Phishing URL ID', input: 'https://secure-hdfc-banking.in/netbanking/login', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Credential-harvest URL structure + impersonation cues' },
  { uc: 'UC 3', name: 'Threat Intel Phishing', input: 'https://login-microsoft365-verify.com/auth', path: '/api/v1/scan', mode: 'Search + Vector Search', technique: 'Threat-intel similarity + lexical enrichment on attack metadata' },
  { uc: 'UC 4', name: 'Gov Impersonation Feed', input: 'https://aadhaar-update-portal.in/ekyc', path: '/api/v1/scan', mode: 'Search + Vector Search', technique: 'Government impersonation matching + phishing refinement rules' },
  { uc: 'UC 5', name: 'Homoglyph/IDN', input: 'https://xn--gogle-mra.com/login', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Homoglyph/IDN detection with similarity-backed evidence' },
  { uc: 'UC 6', name: 'Shortener Abuse', input: 'https://bit.ly/3xR7kQm', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Known shortener detection + redirect-abuse phishing override' },
  { uc: 'UC 7', name: 'Brand Impersonation', input: 'https://icici-bank-rewards.com/claim', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Brand lure semantics + social engineering keywords' },
  { uc: 'UC 8', name: 'Malware Distribution', input: 'https://free-software-download.xyz/adobe-reader-update.exe', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Payload/file pattern severity + malicious URL semantics' },
  { uc: 'UC 9', name: 'Hindi Banking Scam', input: 'URL + Hindi pageContent', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Script detection (hi) + multilingual semantic clustering' },
  { uc: 'UC 10', name: 'Tamil EPFO Scam', input: 'URL + Tamil pageContent', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Script detection (ta) + government impersonation semantic match' },
  { uc: 'UC 11', name: 'Bengali PM-KISAN Scam', input: 'URL + Bengali pageContent', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Script detection (bn) + subsidy-fraud semantic cues' },
  { uc: 'UC 12', name: 'PAN-Aadhaar Scam', input: 'URL + Hindi pageContent', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Tax/government urgency language + phishing patterns' },
  { uc: 'UC 13', name: 'Visual Baseline SBI', input: 'https://onlinesbi.sbi', path: '/api/v1/scan', mode: 'Vector Search (conditional)', technique: 'Trusted baseline posture with low-risk domain and structure' },
  { uc: 'UC 14', name: 'Visual SBI Clone', input: 'https://sbi-secure-login.com/verify', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Clone-like semantics + credential harvesting indicators' },
  { uc: 'UC 15', name: 'Visual Baseline HDFC', input: 'https://hdfcbank.com', path: '/api/v1/scan', mode: 'Vector Search (conditional)', technique: 'Legitimate baseline domain behavior and low-risk scoring' },
  { uc: 'UC 16', name: 'Visual HDFC Clone', input: 'https://secure-hdfc-banking.in/netbanking/login', path: '/api/v1/scan', mode: 'Vector Search', technique: 'Impersonation semantics + suspicious login form indicators' },
  { uc: 'UC 17', name: 'Gov Portal Baseline', input: 'https://eprocure.gov.in', path: '/api/v1/scan', mode: 'Vector Search (conditional)', technique: 'Baseline legitimate portal behavior' },
  { uc: 'UC 18', name: 'Watering Hole Variant', input: 'Gov URL + compromise pageContent', path: '/api/v1/scan', mode: 'Search + Vector Search', technique: 'Injected-script narrative + suspicious supply-chain context' },
  { uc: 'UC 19', name: 'Infra Known Phish Host', input: 'https://sbi-secure-login.com/verify', path: '/api/v1/scan', mode: 'Search + Vector Search', technique: 'Hosting/ASN correlation + threat similarity evidence' },
  { uc: 'UC 20', name: 'Redirect Chain Infra', input: 'https://click-track-offer.com', path: '/api/v1/scan', mode: 'Search', technique: 'Redirect-domain match + risky infra posture' },
  { uc: 'UC 21', name: 'TLS Anomaly Domain', input: 'https://secure-banking-portal.xyz', path: '/api/v1/scan', mode: 'Search', technique: 'TLS anomaly checks + suspicious structure and hosting flags' },
  { uc: 'UC 22', name: 'Fast-Flux Botnet', input: 'https://fast-flux-botnet.top', path: '/api/v1/scan', mode: 'Search', technique: 'IP rotation and TTL-based fast-flux indicators' },
  { uc: 'UC 23', name: 'Fast-Flux Variant', input: 'https://update-service-cdn.buzz', path: '/api/v1/scan', mode: 'Search + Vector Search', technique: 'Rotating infra plus malware/C2-like semantic signals' },
  { uc: 'UC 24', name: 'Supply Chain CDN', input: 'https://cdn-analytics-lib.com/tracker.js', path: '/api/v1/scan', mode: 'Search + Vector Search', technique: 'Compromised script-delivery and supply-chain anomaly cues' },
  { uc: 'UC 25', name: 'Behavior Anomaly', input: 'Target URL or SOC batch input', path: '/api/v1/scan + /api/v1/scan/batch', mode: 'Search', technique: 'RPM/error/timing anomalies + SOC bulk workflow validation' },
];

const UC_RETRIEVAL_GROUPS = [
  {
    cases: 'UC1-UC8, UC13-UC17',
    scenario: 'Core phishing/malware + baseline/clone checks',
    atlas: 'Runs atlas lexical enrichment when threat-intel is enabled',
    vector: '2 vector searches',
    vectorBreakdown: '1x unified urls vector + 1x threat_signals vector',
    conditions: 'embedding available and vector module enabled',
  },
  {
    cases: 'UC9-UC12, UC18',
    scenario: 'Regional language + watering-hole narrative cases',
    atlas: 'Same atlas lexical enrichment path',
    vector: '3 vector searches',
    vectorBreakdown: 'base 2 + 1x regional_threats vector',
    conditions: 'detected_language != en (from pageContent or URL script)',
  },
  {
    cases: 'UC20-UC21, UC25',
    scenario: 'Infrastructure / behavior-heavy cases',
    atlas: 'Same atlas lexical enrichment path',
    vector: '2 vector searches + Search branches',
    vectorBreakdown: 'base 2 vectors; adds infra/behavior Atlas Search branches',
    conditions: 'has_infra_data and/or has_traffic_anomaly',
  },
  {
    cases: 'Visual screenshot-driven investigations',
    scenario: 'When screenshot evidence is available',
    atlas: 'Same atlas lexical enrichment path',
    vector: 'up to 4 vector searches total',
    vectorBreakdown: 'base 2 + regional (optional) + visual_intelligence',
    conditions: 'has_screenshot == true (POC usually false unless enricher fills screenshot_b64)',
  },
];

const RETRIEVAL_RULES = [
  {
    rule: 'Atlas query construction',
    logic: 'query = domain + first two payload types; fuzzy_max_edits=1; limit=8; only threat_intel docs are kept',
  },
  {
    rule: 'Unified vector search',
    logic: 'always 1 call when embedding exists and vectorSearch module is on; searches urls collection for scan + threat_intel neighbors',
  },
  {
    rule: 'threat_signals vector',
    logic: 'always 1 additional vector call in multi-collection fan-out when embedding exists',
  },
  {
    rule: 'regional_threats vector',
    logic: 'only when detected_language != en (Hindi/Tamil/Bengali/etc.)',
  },
  {
    rule: 'visual_intelligence vector',
    logic: 'only when has_screenshot is true',
  },
  {
    rule: 'infrastructure_intel Search',
    logic: 'only when has_infra_data is true; checks domain plus fast-flux/TLS anomaly hints',
  },
  {
    rule: 'behavior_metrics Search',
    logic: 'only when has_traffic_anomaly is true; range checks on RPM, 5xx rate, entropy, timing',
  },
];

const UC_DETAIL_OVERRIDES = {
  1: {
    objective: 'Detect typo-based banking impersonation before credential theft.',
    conditions: 'Brand distance, phishing keywords, and young-domain signals raise phishing confidence.',
    exampleUrl: 'https://sbi-secure-login.com/verify',
    redFlags: [
      'If domain age is less than 100 days, mark as high-risk (newly created impersonation domain).',
      'If brand-like token and login keyword both exist, escalate phishing confidence.',
    ],
  },
  2: {
    objective: 'Catch credential-harvest banking login clones.',
    conditions: 'Structure + impersonation cues trigger vector similarity and deterministic risk boosts.',
    exampleUrl: 'https://secure-hdfc-banking.in/netbanking/login',
    redFlags: [
      'If URL path contains login/auth plus brand name mismatch, flag as impersonation.',
      'If domain is not official bank domain but asks for credentials, raise red flag.',
    ],
  },
  3: {
    objective: 'Correlate with known threat-intel phishing campaigns.',
    conditions: 'Combines semantic neighbors with lexical threat-intel enrichment.',
    exampleUrl: 'https://login-microsoft365-verify.com/auth',
    redFlags: [
      'If Atlas threat-intel docs match campaign tokens, add strong malicious signal.',
      'If vector similarity to known phishing family is high, prioritize block/review action.',
    ],
  },
  4: {
    objective: 'Detect government impersonation lures.',
    conditions: 'Government keyword patterns plus threat-intel enrichment strengthen verdict.',
    exampleUrl: 'https://aadhaar-update-portal.in/ekyc',
    redFlags: [
      'If government authority name appears on non-government domain, flag impersonation.',
      'If KYC/OTP urgency text appears with fake portal domain, classify as phishing risk.',
    ],
  },
  5: {
    objective: 'Catch IDN/punycode homoglyph deception.',
    conditions: 'Homoglyph/visual deception indicators and vector neighbors support classification.',
    exampleUrl: 'https://xn--gogle-mra.com/login',
    redFlags: [
      'If punycode or homoglyph pattern is detected, elevate risk immediately.',
      'If visual similarity to trusted brand is high but domain is unrelated, mark red flag.',
    ],
  },
  6: {
    objective: 'Detect malicious short-link redirection patterns.',
    conditions: 'Shortener and redirect abuse indicators combine with vector threat neighbors.',
    exampleUrl: 'https://bit.ly/3xR7kQm',
    redFlags: [
      'If URL uses public shortener and destination context is unknown, move to review path.',
      'If redirect chain resolves to credential-harvest page, mark as phishing red flag.',
    ],
  },
  7: {
    objective: 'Catch brand reward/offer impersonation scams.',
    conditions: 'Brand lure semantics and payment/OTP harvest patterns drive phishing score.',
    exampleUrl: 'https://icici-bank-rewards.com/claim',
    redFlags: [
      'If reward/offer lure asks for card, CVV, or OTP, mark as high risk.',
      'If domain contains brand token + rewards keyword but is unofficial, raise red flag.',
    ],
  },
  8: {
    objective: 'Flag malware-delivery URLs and payload lures.',
    conditions: 'Executable/dropper semantics plus payload risk indicators increase malware likelihood.',
    exampleUrl: 'https://free-software-download.xyz/adobe-reader-update.exe',
    redFlags: [
      'If URL ends with executable/script payload extension, increase malware score sharply.',
      'If fake update language appears on untrusted domain, classify as malware distribution risk.',
    ],
  },
  9: {
    objective: 'Detect Hindi-language banking scam pages.',
    conditions: 'Non-English signal triggers regional multilingual vector search branch.',
    exampleUrl: 'https://sbi-kyc-update.in/verify',
    redFlags: [
      'If detected language is Hindi and message contains urgent account block warning, flag phishing.',
      'If Aadhaar/KYC + OTP request appears together, raise red flag immediately.',
    ],
  },
  10: {
    objective: 'Detect Tamil government-benefit phishing narratives.',
    conditions: 'Tamil detection routes to regional multilingual vectors and gov-impersonation cues.',
    exampleUrl: 'https://epfo-claim-status.in/check',
    redFlags: [
      'If Tamil text claims government payout and asks for sensitive details, mark suspicious/phishing.',
      'If benefit claim urgency is present on unofficial domain, trigger red flag.',
    ],
  },
  11: {
    objective: 'Detect Bengali subsidy-fraud phishing patterns.',
    conditions: 'Regional multilingual vector branch plus phishing urgency patterns.',
    exampleUrl: 'https://pm-kisan-samman.in/apply',
    redFlags: [
      'If Bengali subsidy text requests identity/bank details, raise phishing alert.',
      'If subsidy claim page uses non-official domain, add red flag evidence.',
    ],
  },
  12: {
    objective: 'Detect PAN-Aadhaar urgency scam narratives.',
    conditions: 'Hindi signals and tax-urgency language increase phishing confidence.',
    exampleUrl: 'https://aadhaar-link-pan.in/update',
    redFlags: [
      'If tax authority warning appears with deadline pressure on unofficial domain, mark high risk.',
      'If PAN/Aadhaar linking request asks for OTP or login credentials, raise red flag.',
    ],
  },
  13: {
    objective: 'Confirm low-risk visual baseline behavior for SBI.',
    conditions: 'Baseline posture remains low risk unless stronger malicious signals appear.',
    exampleUrl: 'https://onlinesbi.sbi',
    redFlags: [
      'If baseline domain remains consistent and no payload anomalies exist, keep low-risk posture.',
      'If baseline suddenly shows suspicious redirect/payload signals, promote to review red flag.',
    ],
  },
  14: {
    objective: 'Detect visual-clone SBI phishing behavior.',
    conditions: 'Clone-like semantics and credential-harvest indicators elevate phishing class.',
    exampleUrl: 'https://sbi-secure-login.com/verify',
    redFlags: [
      'If page resembles SBI login but domain is unofficial, flag as clone phishing.',
      'If credential fields are present with suspicious host traits, mark red flag.',
    ],
  },
  15: {
    objective: 'Confirm low-risk visual baseline behavior for HDFC.',
    conditions: 'Legitimate baseline traits reduce false positives in clone comparisons.',
    exampleUrl: 'https://hdfcbank.com',
    redFlags: [
      'If trusted baseline indicators stay normal, avoid unnecessary escalation.',
      'If baseline site starts showing suspicious payload/redirect signals, switch to review.',
    ],
  },
  16: {
    objective: 'Detect HDFC clone impersonation.',
    conditions: 'Impersonation semantics and suspicious login form structure increase risk.',
    exampleUrl: 'https://secure-hdfc-banking.in/netbanking/login',
    redFlags: [
      'If cloned banking UI appears on non-official domain, raise phishing red flag.',
      'If login form asks for high-risk fields with weak trust signals, escalate risk.',
    ],
  },
  17: {
    objective: 'Validate government portal benign baseline.',
    conditions: 'Benign baseline posture unless infra/behavior anomalies are present.',
    exampleUrl: 'https://eprocure.gov.in',
    redFlags: [
      'If official portal remains stable without anomalies, maintain benign class.',
      'If TLS/infra behavior deviates from baseline, trigger suspicious red flag.',
    ],
  },
  18: {
    objective: 'Identify watering-hole compromised variants.',
    conditions: 'Compromise narrative + non-benign similarity evidence supports suspicious label.',
    exampleUrl: 'https://eprocure.gov.in?variant=compromised',
    redFlags: [
      'If known-safe portal variant loads injected script behavior, mark suspicious.',
      'If page content indicates hidden loader/supply-chain artifacts, raise red flag.',
    ],
  },
  19: {
    objective: 'Correlate known phishing host infrastructure.',
    conditions: 'Infra context + semantic neighbors + lexical enrichment.',
    exampleUrl: 'https://sbi-secure-login.com/verify',
    redFlags: [
      'If hosting/ASN profile overlaps known phishing infra, elevate threat status.',
      'If same domain repeatedly appears in malicious neighbor clusters, add strong red flag.',
    ],
  },
  20: {
    objective: 'Detect redirect-chain infrastructure abuse.',
    conditions: 'Infra search branch prioritized by has_infra_data signal.',
    exampleUrl: 'https://click-track-offer.com',
    redFlags: [
      'If redirect chain length and suspicious relay domains are high, mark suspicious.',
      'If tracking domain routes into known malicious destinations, raise red flag.',
    ],
  },
  21: {
    objective: 'Detect TLS anomaly-driven suspicious domains.',
    conditions: 'Infra branch includes TLS anomaly checks when ssl validity is weak.',
    exampleUrl: 'https://secure-banking-portal.xyz',
    redFlags: [
      'If certificate validity is poor or mismatch/self-signed patterns appear, flag risk.',
      'If TLS anomalies coincide with suspicious TLD and impersonation cues, escalate quickly.',
    ],
  },
  22: {
    objective: 'Detect fast-flux / C2-like infrastructure.',
    conditions: 'Infra/TTL rotation signals plus similarity evidence for C2 behavior.',
    exampleUrl: 'https://fast-flux-botnet.top',
    redFlags: [
      'If IP rotation count is high and TTL is very low, mark fast-flux red flag.',
      'If traffic pattern resembles beaconing/control infrastructure, push toward c2 class.',
    ],
  },
  23: {
    objective: 'Detect fast-flux malware variant evolution.',
    conditions: 'Combines infra search branch with semantic vector evidence.',
    exampleUrl: 'https://update-service-cdn.buzz',
    redFlags: [
      'If domain appears as rotating infra with malware-like neighbors, raise high-risk alert.',
      'If update/cdn lure terms appear on unstable infrastructure, mark red flag.',
    ],
  },
  24: {
    objective: 'Detect supply-chain script delivery abuse.',
    conditions: 'Lexical threat-intel enrichment plus semantic malware/supply-chain neighbors.',
    exampleUrl: 'https://cdn-analytics-lib.com/tracker.js',
    redFlags: [
      'If third-party script delivery domain has malicious intel matches, escalate risk.',
      'If script endpoint behaves unlike trusted CDN baseline, add supply-chain red flag.',
    ],
  },
  25: {
    objective: 'Detect traffic/behavior anomalies in SOC workflows.',
    conditions: 'Behavior search branch triggered by traffic anomaly indicators.',
    exampleUrl: 'https://task-sync-control-panel.top/api/pulse',
    redFlags: [
      'If requests per minute spikes above normal with short inter-request gap, flag anomaly.',
      'If high error ratio and bot-like timing pattern appear together, raise red flag.',
    ],
  },
};

const EMBEDDING_STRATEGY_TEXT = {
  primary: 'Primary embedding path: summaryText is embedded using voyage-4 style 1024-d vectors for unified urls similarity.',
  regional: 'Regional branch: voyage-multilingual-2 style embedding is used when detected_language != en.',
  visual: 'Visual branch: voyage-multimodal-3 style embedding is used only when screenshot signal exists.',
  campaign: 'Campaign strategy: campaign-enriched summary is re-embedded to improve future one-query retrieval quality.',
};

function getUcNumber(ucLabel) {
  const n = Number(String(ucLabel || '').replace(/[^0-9]/g, ''));
  return Number.isFinite(n) ? n : 0;
}

function normalizeRedFlags(flags) {
  return (flags || []).map((f) => {
    if (typeof f === 'string') {
      const lower = f.toLowerCase();
      const severity = lower.includes('high') || lower.includes('immediately') || lower.includes('sharply')
        ? 'high'
        : lower.includes('review') || lower.includes('suspicious')
          ? 'medium'
          : 'low';
      return { text: f, severity };
    }
    return {
      text: f.text,
      severity: f.severity || 'medium',
    };
  });
}

function getUseCaseDetails(row) {
  const ucNo = getUcNumber(row.uc);
  const hasVector = row.mode.includes('Vector');
  const hasSearch = row.mode.includes('Search');
  const isRegional = ucNo >= 9 && ucNo <= 12;
  const isWatering = ucNo === 18;
  const isInfraHeavy = ucNo === 20 || ucNo === 21 || ucNo === 25;
  const isVisualConditional = row.mode.includes('(conditional)');

  const vectorCount = !hasVector
    ? '0 vector calls'
    : isRegional || isWatering
      ? '3 vector calls (urls + threat_signals + regional_threats)'
      : isVisualConditional
        ? '2 vector calls by default (urls + threat_signals), visual_intelligence added only if screenshot exists'
        : '2 vector calls (urls + threat_signals)';

  const atlasWhy = hasSearch
    ? 'Atlas lexical enrichment is used to recover threat-intel context (attack category/payload signatures) and improve explainability.'
    : 'Atlas lexical enrichment is optional; primary decision path is semantic vector + deterministic heuristics.';

  const searchBranch = isInfraHeavy
    ? 'Search branch focus: infrastructure_intel and/or behavior_metrics indexes due to infra/anomaly signals.'
    : hasSearch
      ? 'Search branch focus: url_search_index threat-intel enrichment plus conditional infra/behavior branches.'
      : 'Search branch is not primary for this case unless additional infra/anomaly triggers appear.';

  const example = hasSearch
    ? 'Example query flow: atlas_query = domain + payloadTypes[:2], fuzzy_max_edits=1, limit=8, keep docType=threat_intel.'
    : 'Example query flow: embed summaryText, run vector search in urls + threat_signals, merge with rule-based signals.';

  return {
    objective: (UC_DETAIL_OVERRIDES[ucNo] || {}).objective || row.technique,
    conditions: (UC_DETAIL_OVERRIDES[ucNo] || {}).conditions || 'Standard pipeline thresholds and hard-floor rules apply.',
    exampleUrl: (UC_DETAIL_OVERRIDES[ucNo] || {}).exampleUrl || row.input,
    redFlags: normalizeRedFlags((UC_DETAIL_OVERRIDES[ucNo] || {}).redFlags || [
      { text: 'If domain age is less than 100 days, suggest red flag for newly created threat infrastructure.', severity: 'high' },
      { text: 'If phishing/malware keywords and suspicious hosting signals appear together, escalate review severity.', severity: 'medium' },
    ]),
    retrievalWhy: row.mode === 'Search + Vector Search'
      ? 'Combination mode is used to blend semantic similarity (vector) with lexical/structured intel context (search).'
      : row.mode.includes('Vector')
        ? 'Vector-first mode is used because semantic similarity captures attack-family patterns even with lexical variation.'
        : 'Search-first mode is used because infra/behavior signals are better represented by structured range/text conditions.',
    vectorCount,
    atlasWhy,
    searchBranch,
    example,
    embeddingModel: isRegional || isWatering
      ? `${EMBEDDING_STRATEGY_TEXT.primary} ${EMBEDDING_STRATEGY_TEXT.regional}`
      : isVisualConditional
        ? `${EMBEDDING_STRATEGY_TEXT.primary} ${EMBEDDING_STRATEGY_TEXT.visual}`
        : EMBEDDING_STRATEGY_TEXT.primary,
    indexStrategy: 'Indexes used: url_vector_index (unified urls), vs_threat_signals (threat_signals), vs_regional (regional, conditional), vs_visual (visual, conditional), url_search_index (lexical enrichment), infra_search_index and behavior_search_index (conditional branches).',
    embeddedStrategy: EMBEDDING_STRATEGY_TEXT.campaign,
  };
}

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
  const [selectedUseCase, setSelectedUseCase] = useState(null);

  const viewTitle = useMemo(() => {
    if (activeView === 'usecase') return 'Use Case Test Logic (UC 1-25)';
    if (activeView === 'agentic') return 'Agentic Architecture';
    if (activeView === 'comparison') return 'Pipeline vs Agentic Comparison';
    if (activeView === 'flow') return 'Scanner Flow Diagram';
    if (activeView === 'url-search-flow') return 'URL Search Flow';
    if (activeView === 'search-features') return 'Atlas Search + Vector Search Features';
    if (activeView === 'collections') return 'Collections, Sample Data, and Embedding Strategy';
    if (activeView === 'stack') return 'Tech Stack, Models, and Module Purposes';
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
          This page shows both analysis architectures used by the scanner: Pipeline mode for deterministic scoring, and Agentic mode where Microsoft Foundry reasons over pipeline evidence. The current default uses one classifier agent, while multi-agent chains can be enabled for more agentic workflows.
        </div>
      </div>

      <div style={card}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
          {[
            { key: 'pipeline', label: 'Pipeline Architecture' },
            { key: 'usecase', label: 'Use Case Test Logic' },
            { key: 'agentic', label: 'Agentic Architecture' },
            { key: 'comparison', label: 'Compare Both' },
            { key: 'flow', label: 'Scanner Flow Diagram' },
            { key: 'url-search-flow', label: 'URL Search Flow' },
            { key: 'search-features', label: 'Search Features Used' },
            { key: 'collections', label: 'Collections & Data Flow' },
            { key: 'stack', label: 'Tech Stack & Models' },
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

      {activeView === 'usecase' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e' }}>UC 1-25 Testing Architecture</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <FeaturePill>Heuristic Engine</FeaturePill>
                <FeaturePill bg="#F3EEFF" color="#4B2B91">Vector Search</FeaturePill>
                <FeaturePill bg="#E3FCF7" color="#0F5132">Search</FeaturePill>
              </div>
            </div>

            <p style={{ fontSize: 13, color: '#5C6C75', lineHeight: 1.6, marginTop: 0, marginBottom: 14 }}>
              This table shows how each use case is currently executed in production: input style, endpoint path, retrieval strategy,
              and detection technique. For multilingual cases, include pageContent to activate language-aware routing.
            </p>

            <div style={{ border: '1px solid #D9E7F8', borderRadius: 12, background: 'linear-gradient(180deg, #F8FBFF 0%, #F2F7FF 100%)', padding: 14, marginBottom: 14 }}>
              <div style={{ fontSize: 14, fontWeight: 800, color: '#12344D', marginBottom: 10 }}>
                UC1-UC25 Quick Legend (30-second read)
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 8 }}>
                {[
                  'Base flow for almost all cases: 2 vector calls (urls + threat_signals).',
                  'Regional cases (UC9-UC12, UC18): +1 regional vector call when language is non-English.',
                  'Visual vector path: only when screenshot signal exists (has_screenshot=true).',
                  'Infra cases (UC20-UC21): add Search path when infra signals are present.',
                  'Behavior case (UC25): add Search path when traffic anomaly flag is present.',
                  'Atlas enrichment runs with domain + payload hints, keeps only threat_intel docs.',
                  'Final decision always merges heuristics + vector/search evidence + thresholds.',
                ].map((line) => (
                  <div key={line} style={{ background: '#fff', border: '1px solid #DCE7F5', borderRadius: 8, padding: '8px 10px', fontSize: 12, color: '#2B4A66', lineHeight: 1.5 }}>
                    {line}
                  </div>
                ))}
              </div>
            </div>

            <div style={{ border: '1px solid #E8EDEB', borderRadius: 12, background: '#F9FAFB', padding: 14, marginBottom: 14 }}>
              <div style={{ fontSize: 14, fontWeight: 800, color: '#1a1c1e', marginBottom: 10 }}>How One URL Scan Runs (Exact Runtime Order)</div>
              <div style={{ display: 'grid', gap: 8 }}>
                {[
                  '1) Build features and summary text from URL + optional pageContent.',
                  '2) Create/reuse embedding.',
                  '3) Run unified vector search on urls (scan + threat_intel docs).',
                  '4) Run conditional multi-collection fan-out: threat_signals always, regional only for non-English, visual only for screenshot, infrastructure/behavior via Search on signal triggers.',
                  '5) Run Atlas lexical enrichment query (domain + payload hints) for threat-intel context.',
                  '6) Merge evidence, score risk, classify, refine status, persist, return.',
                ].map((line) => (
                  <div key={line} style={{ background: '#fff', border: '1px solid #E8EDEB', borderRadius: 8, padding: '8px 10px', fontSize: 12, color: '#3D4F58', lineHeight: 1.5 }}>
                    {line}
                  </div>
                ))}
              </div>
            </div>

            <div style={{ border: '1px solid #E8EDEB', borderRadius: 12, background: '#FBFDFF', padding: 14, marginBottom: 14 }}>
              <div style={{ fontSize: 14, fontWeight: 800, color: '#1a1c1e', marginBottom: 10 }}>Atlas Search Query (Used During Scan Enrichment)</div>
              <div style={{ background: '#0F172A', borderRadius: 10, padding: 12, overflowX: 'auto' }}>
                <pre style={{ margin: 0, fontSize: 12, color: '#D6E4FF', whiteSpace: 'pre-wrap' }}>{`atlas_query = [domain] + payloadTypes[:2]
atlas.search(
  query=atlas_query,
  fuzzy_max_edits=1,
  limit=8
)
post-filter: keep docType == "threat_intel"`}</pre>
              </div>
              <div style={{ marginTop: 8, fontSize: 12, color: '#3D4F58', lineHeight: 1.5 }}>
                Atlas lexical enrichment runs when Atlas + threat-intel modules are enabled. It adds attack category/payload signatures into scoring context.
              </div>
            </div>

            <div style={{ overflowX: 'auto', border: '1px solid #E8EDEB', borderRadius: 12, marginBottom: 14 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 980 }}>
                <thead>
                  <tr style={{ background: '#F5F6F7' }}>
                    {['UC Range / Type', 'Scenario Group', 'Atlas Query Use', 'Vector Search Count', 'Vector Breakdown', 'Trigger Conditions'].map((h) => (
                      <th key={h} style={{ textAlign: 'left', padding: '10px 12px', fontSize: 12, color: '#3D4F58', borderBottom: '1px solid #E8EDEB' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {UC_RETRIEVAL_GROUPS.map((row, idx) => (
                    <tr key={row.cases} style={{ background: idx % 2 === 0 ? '#fff' : '#FBFDFF' }}>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, fontWeight: 700, color: '#1a1c1e' }}>{row.cases}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#3D4F58' }}>{row.scenario}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#0F5132', fontWeight: 700 }}>{row.atlas}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#4B2B91', fontWeight: 700 }}>{row.vector}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#3D4F58' }}>{row.vectorBreakdown}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#3D4F58' }}>{row.conditions}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ overflowX: 'auto', border: '1px solid #E8EDEB', borderRadius: 12, marginBottom: 14 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 820 }}>
                <thead>
                  <tr style={{ background: '#F5F6F7' }}>
                    {['Routing Rule', 'Condition / Query Logic'].map((h) => (
                      <th key={h} style={{ textAlign: 'left', padding: '10px 12px', fontSize: 12, color: '#3D4F58', borderBottom: '1px solid #E8EDEB' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {RETRIEVAL_RULES.map((row, idx) => (
                    <tr key={row.rule} style={{ background: idx % 2 === 0 ? '#fff' : '#FBFDFF' }}>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, fontWeight: 700, color: '#1a1c1e' }}>{row.rule}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#3D4F58', lineHeight: 1.5 }}>{row.logic}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10, marginBottom: 14 }}>
              <div style={{ background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 12, color: '#3D4F58' }}>
                <strong style={{ color: '#1a1c1e' }}>Primary endpoint:</strong> /api/v1/scan
              </div>
              <div style={{ background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 12, color: '#3D4F58' }}>
                <strong style={{ color: '#1a1c1e' }}>SOC mode:</strong> /api/v1/scan/batch, /api/v1/scan/batch/csv
              </div>
              <div style={{ background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 12, color: '#3D4F58' }}>
                <strong style={{ color: '#1a1c1e' }}>Waterfall:</strong> L1 cache - L2 DB - L3 full pipeline
              </div>
            </div>

            <div style={{ overflowX: 'auto', border: '1px solid #E8EDEB', borderRadius: 12 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 1020 }}>
                <thead>
                  <tr style={{ background: '#F5F6F7' }}>
                    {['Use Case', 'Scenario', 'Input', 'Path', 'Retrieval Mode', 'Technique', 'Info'].map((h) => (
                      <th key={h} style={{ textAlign: 'left', padding: '10px 12px', fontSize: 12, color: '#3D4F58', borderBottom: '1px solid #E8EDEB' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {UC_TEST_CASES.map((row, idx) => (
                    <tr key={row.uc} style={{ background: idx % 2 === 0 ? '#fff' : '#FBFDFF' }}>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, fontWeight: 700, color: '#1a1c1e' }}>{row.uc}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#1a1c1e' }}>{row.name}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#3D4F58' }}>{row.input}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#12344D', fontFamily: 'monospace' }}>{row.path}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#4B2B91', fontWeight: 700 }}>{row.mode}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#3D4F58', lineHeight: 1.45 }}>{row.technique}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12 }}>
                        <button
                          onClick={() => setSelectedUseCase(row)}
                          style={{
                            width: 24,
                            height: 24,
                            borderRadius: 999,
                            border: '1px solid #B8CCE8',
                            background: '#EEF5FF',
                            color: '#0A4B9F',
                            fontSize: 12,
                            fontWeight: 800,
                            cursor: 'pointer',
                          }}
                          title={`More details for ${row.uc}`}
                          aria-label={`More details for ${row.uc}`}
                        >
                          i
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selectedUseCase && (
              <div
                onClick={() => setSelectedUseCase(null)}
                style={{
                  position: 'fixed',
                  inset: 0,
                  background: 'rgba(1, 30, 43, 0.45)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  padding: 16,
                  zIndex: 1100,
                }}
              >
                <div
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    width: 'min(980px, 100%)',
                    maxHeight: '85vh',
                    overflowY: 'auto',
                    border: '1px solid #D9E7F8',
                    borderRadius: 12,
                    background: '#F8FBFF',
                    padding: 14,
                    boxShadow: '0 20px 48px rgba(0,0,0,0.22)',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 10 }}>
                    <div>
                      <div style={{ fontSize: 15, fontWeight: 800, color: '#12344D' }}>{selectedUseCase.uc} - {selectedUseCase.name}</div>
                      <div style={{ fontSize: 12, color: '#3D4F58' }}>Detailed rationale for retrieval, embedding, and index strategy</div>
                    </div>
                    <button
                      onClick={() => setSelectedUseCase(null)}
                      style={{ border: '1px solid #B8CCE8', borderRadius: 8, background: '#fff', color: '#12344D', fontSize: 12, fontWeight: 700, padding: '6px 10px', cursor: 'pointer' }}
                    >
                      Close
                    </button>
                  </div>

                  <div style={{ display: 'grid', gap: 8 }}>
                    {(() => {
                      const detail = getUseCaseDetails(selectedUseCase);
                      return [
                        ['Use Case Goal', detail.objective],
                        ['Example URL', detail.exampleUrl],
                        ['Why This Retrieval Mode', detail.retrievalWhy],
                        ['Vector Search Count', detail.vectorCount],
                        ['Atlas Search Rationale', detail.atlasWhy],
                        ['Search Branch Behavior', detail.searchBranch],
                        ['Condition Triggers', detail.conditions],
                        ['Example Query Path', detail.example],
                        ['Embedding Model Strategy', detail.embeddingModel],
                        ['Index Strategy', detail.indexStrategy],
                        ['Embedded Strategy', detail.embeddedStrategy],
                      ].map(([label, value]) => (
                        <div key={label} style={{ background: '#fff', border: '1px solid #DCE7F5', borderRadius: 8, padding: '8px 10px' }}>
                          <div style={{ fontSize: 12, fontWeight: 800, color: '#12344D', marginBottom: 2 }}>{label}</div>
                          <div style={{ fontSize: 12, color: '#3D4F58', lineHeight: 1.5 }}>{value}</div>
                        </div>
                      ));
                    })()}

                    <div style={{ background: '#fff', border: '1px solid #DCE7F5', borderRadius: 8, padding: '8px 10px' }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: '#12344D', marginBottom: 6 }}>Human-Readable Red Flags</div>
                      <div style={{ display: 'grid', gap: 6 }}>
                        {getUseCaseDetails(selectedUseCase).redFlags.map((item) => {
                          const severityColors = item.severity === 'high'
                            ? { bg: '#FFE8E5', color: '#9C2B10', border: '#F3C2B7' }
                            : item.severity === 'medium'
                              ? { bg: '#FFF6E8', color: '#8A5A00', border: '#F0D6A2' }
                              : { bg: '#EAFBF2', color: '#1C6A43', border: '#BEE5CD' };
                          return (
                            <div key={item.text} style={{ fontSize: 12, color: '#3D4F58', lineHeight: 1.5, background: '#F7FAFF', border: '1px solid #E2ECFB', borderRadius: 6, padding: '6px 8px' }}>
                              <span style={{ display: 'inline-flex', alignItems: 'center', padding: '2px 8px', borderRadius: 999, fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.2px', marginRight: 8, background: severityColors.bg, color: severityColors.color, border: `1px solid ${severityColors.border}` }}>
                                {item.severity}
                              </span>
                              {item.text}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div style={card}>
            <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e', marginBottom: 14 }}>High-Level URL Scanning Steps</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[
                '1. URL and optional pageContent are received at /api/v1/scan.',
                '2. Waterfall check runs: L1 cache, then L2 database, then L3 full pipeline if needed.',
                '3. URL signals are extracted: domain, structure, payload patterns, DGA, homoglyph, brand cues.',
                '4. Context signals are derived from pageContent (language and phishing text patterns).',
                '5. Summary text is generated for scoring and retrieval.',
                '6. Embedding is generated or reused from existing records.',
                '7. Vector Search and Search are run based on detected signals.',
                '8. Risk score and threat classification are computed and refined.',
                '9. Final status is assigned (blocked, under_review, allowed).',
                '10. Record is stored and response is returned with evidence breakdown.',
              ].map((line) => (
                <div key={line} style={{ background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13, color: '#3D4F58', lineHeight: 1.5 }}>
                  {line}
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e', marginBottom: 14 }}>Collections: Search and Embedding Logic</h3>
            <div style={{ overflowX: 'auto', border: '1px solid #E8EDEB', borderRadius: 12 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 960 }}>
                <thead>
                  <tr style={{ background: '#F5F6F7' }}>
                    {['Collection', 'What It Stores', 'How It Is Queried', 'Embedding Usage'].map((h) => (
                      <th key={h} style={{ textAlign: 'left', padding: '10px 12px', fontSize: 12, color: '#3D4F58', borderBottom: '1px solid #E8EDEB' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['urls and threat corpus', 'Historical scans + threat-intel style records', 'Vector Search + Search enrichment', 'Scan summary embedding generated or reused'],
                    ['threat_signals', 'Core phishing/malware/c2/campaign patterns', 'Vector Search', 'Threat text embeddings used for semantic matching'],
                    ['regional_threats', 'Hindi/Tamil/Bengali regional scam patterns', 'Vector Search (multilingual)', 'Triggered mainly when non-English signals are detected'],
                    ['visual_intelligence', 'Visual baseline and impersonation descriptors', 'Vector Search (conditional)', 'Used when visual/screenshot-like signal exists'],
                    ['infrastructure_intel', 'DNS, TLS, redirect and hosting indicators', 'Search', 'No embedding required for query path'],
                    ['behavior_metrics', 'Traffic and anomaly metrics', 'Search', 'No embedding required for query path'],
                  ].map((row, idx) => (
                    <tr key={row[0]} style={{ background: idx % 2 === 0 ? '#fff' : '#FBFDFF' }}>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#1a1c1e', fontWeight: 700 }}>{row[0]}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#3D4F58' }}>{row[1]}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#4B2B91', fontWeight: 700 }}>{row[2]}</td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #E8EDEB', fontSize: 12, color: '#3D4F58', lineHeight: 1.45 }}>{row[3]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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
              The default single-agent mode keeps latency and operations simpler; configurable multi-agent chains can be used when you want more agentic orchestration.
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
              <div><strong>Agent chain:</strong> Configurable via <code>AGENTIC_AGENT_CHAIN</code> env var (default: classifier). You can keep the current single-agent mode or compose multiple agents for more agentic workflows. Custom prompts via <code>AGENTIC_AGENT_PROMPTS_JSON</code>.</div>
              <div><strong>Model:</strong> Microsoft Foundry endpoint using <code>gpt-5.4</code> with temperature 0.2 and JSON response format for structured outputs.</div>
              <div><strong>Client timeout:</strong> 90s safety timeout; single-agent runs usually complete faster, while multi-agent chains may take longer.</div>
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
              ['Agent count', 'None (deterministic)', 'Default: 1 agent (classifier); optional multi-agent chain'],
              ['Latency profile', 'Lower and predictable', 'Higher than pipeline; single-agent is faster than multi-agent chains'],
              ['Explainability', 'Formula + rule evidence', 'Agent reasoning steps + decisive signals'],
              ['Failure behavior', 'Always available if backend up', 'Pipeline result returned; Foundry-unavailable state surfaced in UI'],
              ['Request timeout', '30s client timeout', '90s client timeout safety window'],
              ['Score adjustment', 'N/A (formula only)', 'Current classifier agent applies -15 to +15 adjustment to pipeline baseline'],
              ['Best use', 'Strict policy enforcement', 'Analyst assist, second-opinion, and explainable verdicts; multi-agent chains fit deeper agentic workflows'],
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: 17, color: '#1a1c1e' }}>URL Search Flow Diagram</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <FeaturePill bg="#F3EEFF" color="#4B2B91">Vector Search</FeaturePill>
                <FeaturePill bg="#E3FCF7" color="#0F5132">Search</FeaturePill>
              </div>
            </div>

            <p style={{ fontSize: 13, color: '#5C6C75', lineHeight: 1.6, marginTop: 0, marginBottom: 12 }}>
              This flow shows how one URL is processed, when each retrieval path is used, and how evidence is merged before final scoring.
            </p>

            <div style={{
              border: '1px solid #E8EDEB',
              borderRadius: 12,
              background: 'linear-gradient(180deg, #FBFDFD 0%, #F5F8F8 100%)',
              padding: 12,
              overflowX: 'auto',
            }}>
              <svg viewBox="0 0 1120 360" width="100%" role="img" aria-label="URL search flow diagram" style={{ minWidth: 860 }}>
                <defs>
                  <marker id="urlSearchArrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                    <polygon points="0 0, 10 3.5, 0 7" fill="#3D4F58" />
                  </marker>
                </defs>

                <rect x="20" y="24" rx="12" ry="12" width="150" height="56" fill="#E8F4FD" stroke="#98C4F5" />
                <text x="95" y="57" textAnchor="middle" fontSize="12" fontWeight="700" fill="#12344D">URL Input</text>

                <rect x="220" y="24" rx="12" ry="12" width="210" height="56" fill="#FFF6E8" stroke="#F0D6A2" />
                <text x="325" y="49" textAnchor="middle" fontSize="12" fontWeight="700" fill="#6B4E13">Feature + Signal Build</text>
                <text x="325" y="66" textAnchor="middle" fontSize="11" fill="#6B4E13">URL + optional pageContent</text>

                <rect x="480" y="24" rx="12" ry="12" width="210" height="56" fill="#F3EEFF" stroke="#CDBAF6" />
                <text x="585" y="49" textAnchor="middle" fontSize="12" fontWeight="700" fill="#4B2B91">Summary + Embedding</text>
                <text x="585" y="66" textAnchor="middle" fontSize="11" fill="#4B2B91">Create or reuse vector</text>

                <line x1="170" y1="52" x2="220" y2="52" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrow)" />
                <line x1="430" y1="52" x2="480" y2="52" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrow)" />

                <rect x="120" y="138" rx="12" ry="12" width="260" height="78" fill="#F3EEFF" stroke="#CDBAF6" />
                <text x="250" y="166" textAnchor="middle" fontSize="12" fontWeight="700" fill="#4B2B91">Vector Search Branch</text>
                <text x="250" y="184" textAnchor="middle" fontSize="11" fill="#4B2B91">threat_signals + regional + visual</text>
                <text x="250" y="200" textAnchor="middle" fontSize="11" fill="#4B2B91">semantic similarity matches</text>

                <rect x="430" y="138" rx="12" ry="12" width="260" height="78" fill="#E3FCF7" stroke="#A2E8DA" />
                <text x="560" y="166" textAnchor="middle" fontSize="12" fontWeight="700" fill="#0F5132">Search Branch</text>
                <text x="560" y="184" textAnchor="middle" fontSize="11" fill="#0F5132">infrastructure + behavior + intel text</text>
                <text x="560" y="200" textAnchor="middle" fontSize="11" fill="#0F5132">structured and lexical evidence</text>

                <line x1="585" y1="80" x2="250" y2="138" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrow)" />
                <line x1="585" y1="80" x2="560" y2="138" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrow)" />

                <rect x="730" y="138" rx="12" ry="12" width="330" height="78" fill="#E8F4FD" stroke="#98C4F5" />
                <text x="895" y="166" textAnchor="middle" fontSize="12" fontWeight="700" fill="#12344D">Evidence Merge Layer</text>
                <text x="895" y="184" textAnchor="middle" fontSize="11" fill="#12344D">combine vector + search signals</text>
                <text x="895" y="200" textAnchor="middle" fontSize="11" fill="#12344D">dedupe, rank, and build explanation context</text>

                <line x1="380" y1="177" x2="730" y2="177" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrow)" />
                <line x1="690" y1="177" x2="730" y2="177" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrow)" />

                <rect x="730" y="264" rx="12" ry="12" width="160" height="56" fill="#FFF6E8" stroke="#F0D6A2" />
                <text x="810" y="289" textAnchor="middle" fontSize="12" fontWeight="700" fill="#6B4E13">Risk Scoring</text>
                <text x="810" y="306" textAnchor="middle" fontSize="11" fill="#6B4E13">class + status</text>

                <rect x="910" y="264" rx="12" ry="12" width="170" height="56" fill="#EAFBF2" stroke="#9DDFC1" />
                <text x="995" y="289" textAnchor="middle" fontSize="12" fontWeight="700" fill="#1C6A43">Persist + Return</text>
                <text x="995" y="306" textAnchor="middle" fontSize="11" fill="#1C6A43">evidence-rich response</text>

                <line x1="895" y1="216" x2="810" y2="264" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrow)" />
                <line x1="890" y1="292" x2="910" y2="292" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrow)" />
              </svg>
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

      {activeView === 'url-search-flow' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: 17, color: '#1a1c1e' }}>URL Search Flow Diagram</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <FeaturePill bg="#F3EEFF" color="#4B2B91">Vector Search</FeaturePill>
                <FeaturePill bg="#E3FCF7" color="#0F5132">Search</FeaturePill>
              </div>
            </div>

            <p style={{ fontSize: 13, color: '#5C6C75', lineHeight: 1.6, marginTop: 0, marginBottom: 12 }}>
              One URL enters the scanner, runs through signal extraction and embedding, branches into Vector Search and Search,
              then merges evidence for final risk scoring and response.
            </p>

            <div style={{
              border: '1px solid #E8EDEB',
              borderRadius: 12,
              background: 'linear-gradient(180deg, #FBFDFD 0%, #F5F8F8 100%)',
              padding: 12,
              overflowX: 'auto',
            }}>
              <svg viewBox="0 0 1120 360" width="100%" role="img" aria-label="URL search flow diagram" style={{ minWidth: 860 }}>
                <defs>
                  <marker id="urlSearchArrowStandalone" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                    <polygon points="0 0, 10 3.5, 0 7" fill="#3D4F58" />
                  </marker>
                </defs>

                <rect x="20" y="24" rx="12" ry="12" width="150" height="56" fill="#E8F4FD" stroke="#98C4F5" />
                <text x="95" y="57" textAnchor="middle" fontSize="12" fontWeight="700" fill="#12344D">URL Input</text>

                <rect x="220" y="24" rx="12" ry="12" width="210" height="56" fill="#FFF6E8" stroke="#F0D6A2" />
                <text x="325" y="49" textAnchor="middle" fontSize="12" fontWeight="700" fill="#6B4E13">Feature + Signal Build</text>
                <text x="325" y="66" textAnchor="middle" fontSize="11" fill="#6B4E13">URL + optional pageContent</text>

                <rect x="480" y="24" rx="12" ry="12" width="210" height="56" fill="#F3EEFF" stroke="#CDBAF6" />
                <text x="585" y="49" textAnchor="middle" fontSize="12" fontWeight="700" fill="#4B2B91">Summary + Embedding</text>
                <text x="585" y="66" textAnchor="middle" fontSize="11" fill="#4B2B91">Create or reuse vector</text>

                <line x1="170" y1="52" x2="220" y2="52" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrowStandalone)" />
                <line x1="430" y1="52" x2="480" y2="52" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrowStandalone)" />

                <rect x="120" y="138" rx="12" ry="12" width="260" height="78" fill="#F3EEFF" stroke="#CDBAF6" />
                <text x="250" y="166" textAnchor="middle" fontSize="12" fontWeight="700" fill="#4B2B91">Vector Search Branch</text>
                <text x="250" y="184" textAnchor="middle" fontSize="11" fill="#4B2B91">threat_signals + regional + visual</text>
                <text x="250" y="200" textAnchor="middle" fontSize="11" fill="#4B2B91">semantic similarity matches</text>

                <rect x="430" y="138" rx="12" ry="12" width="260" height="78" fill="#E3FCF7" stroke="#A2E8DA" />
                <text x="560" y="166" textAnchor="middle" fontSize="12" fontWeight="700" fill="#0F5132">Search Branch</text>
                <text x="560" y="184" textAnchor="middle" fontSize="11" fill="#0F5132">infrastructure + behavior + intel text</text>
                <text x="560" y="200" textAnchor="middle" fontSize="11" fill="#0F5132">structured and lexical evidence</text>

                <line x1="585" y1="80" x2="250" y2="138" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrowStandalone)" />
                <line x1="585" y1="80" x2="560" y2="138" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrowStandalone)" />

                <rect x="730" y="138" rx="12" ry="12" width="330" height="78" fill="#E8F4FD" stroke="#98C4F5" />
                <text x="895" y="166" textAnchor="middle" fontSize="12" fontWeight="700" fill="#12344D">Evidence Merge Layer</text>
                <text x="895" y="184" textAnchor="middle" fontSize="11" fill="#12344D">combine vector + search signals</text>
                <text x="895" y="200" textAnchor="middle" fontSize="11" fill="#12344D">dedupe, rank, and build explanation context</text>

                <line x1="380" y1="177" x2="730" y2="177" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrowStandalone)" />
                <line x1="690" y1="177" x2="730" y2="177" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrowStandalone)" />

                <rect x="730" y="264" rx="12" ry="12" width="160" height="56" fill="#FFF6E8" stroke="#F0D6A2" />
                <text x="810" y="289" textAnchor="middle" fontSize="12" fontWeight="700" fill="#6B4E13">Risk Scoring</text>
                <text x="810" y="306" textAnchor="middle" fontSize="11" fill="#6B4E13">class + status</text>

                <rect x="910" y="264" rx="12" ry="12" width="170" height="56" fill="#EAFBF2" stroke="#9DDFC1" />
                <text x="995" y="289" textAnchor="middle" fontSize="12" fontWeight="700" fill="#1C6A43">Persist + Return</text>
                <text x="995" y="306" textAnchor="middle" fontSize="11" fill="#1C6A43">evidence-rich response</text>

                <line x1="895" y1="216" x2="810" y2="264" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrowStandalone)" />
                <line x1="890" y1="292" x2="910" y2="292" stroke="#3D4F58" strokeWidth="2" markerEnd="url(#urlSearchArrowStandalone)" />
              </svg>
            </div>
          </div>
        </div>
      )}

      {activeView === 'collections' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 18, color: '#1a1c1e' }}>
              Collection Usage Map
            </h3>
            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['urls', 'Primary unified store for scanner records + threat intel docs', 'Source: URL Scanner API, reset/seed scripts, threat-intel seed script'],
                ['campaigns', 'Clustered attack campaigns and aggregate stats (urlCount, avgRiskScore, lastSeen)', 'Source: campaign detection service during scan and seeding scripts'],
                ['url_edges', 'Graph relationships between related URLs for traversal/connected evidence', 'Source: URL graph service after scan similarity results'],
                ['scan_rules', 'Active threshold weights, module toggles, and policy defaults', 'Source: default rules on first run + scan rules admin routes'],
                ['threat_logs', 'Operational/audit log history for analytics and review timelines', 'Source: seed/demo scripts and threat management flows'],
              ].map(([name, purpose, source]) => (
                <div key={name} style={{ display: 'grid', gridTemplateColumns: '150px 1fr 1fr', gap: 12, background: '#F9FAFB', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13 }}>
                  <div style={{ fontWeight: 800, color: '#1a1c1e', fontFamily: 'monospace' }}>{name}</div>
                  <div style={{ color: '#3D4F58' }}>{purpose}</div>
                  <div style={{ color: '#3D4F58' }}>{source}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 18, color: '#1a1c1e' }}>
              Sample Data By Collection
            </h3>
            <div style={{ display: 'grid', gap: 14 }}>
              <div style={{ border: '1px solid #E8EDEB', borderRadius: 10, padding: 12, background: '#FBFDFF' }}>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, color: '#1a1c1e' }}>urls (scanner record)</div>
                <pre style={{ margin: 0, fontSize: 12, color: '#12344D', whiteSpace: 'pre-wrap' }}>{`{
  "url": "https://secure-login-incometax.xyz/auth/verify",
  "domain": "secure-login-incometax.xyz",
  "docType": "scan",
  "threatClassification": "phishing",
  "riskScore": 86.4,
  "status": "blocked",
  "summaryText": "URL analysis ... threat classification phishing ...",
  "embedding": [/* 1024-dim voyage-4 vector */],
  "campaignId": "campaign_001_tax_auth_2025",
  "campaignName": "Tax Authority Phishing Campaign Q1 2025"
}`}</pre>
              </div>

              <div style={{ border: '1px solid #E8EDEB', borderRadius: 10, padding: 12, background: '#FCFAFF' }}>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, color: '#1a1c1e' }}>urls (threat intel doc in same collection)</div>
                <pre style={{ margin: 0, fontSize: 12, color: '#4B2B91', whiteSpace: 'pre-wrap' }}>{`{
  "url": "https://nic.in/login?redirect=http://gov-login-verify.xyz/capture",
  "domain": "nic.in",
  "docType": "threat_intel",
  "threatClassification": "phishing",
  "attackCategory": "open_redirect",
  "feedName": "CERT-IN_Feed",
  "summaryText": "Open redirect attack against nic.in ...",
  "embedding": [/* 1024-dim voyage-4 vector */]
}`}</pre>
              </div>

              <div style={{ border: '1px solid #E8EDEB', borderRadius: 10, padding: 12, background: '#F6FBF8' }}>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, color: '#1a1c1e' }}>campaigns</div>
                <pre style={{ margin: 0, fontSize: 12, color: '#1C6A43', whiteSpace: 'pre-wrap' }}>{`{
  "campaignId": "campaign_001_tax_auth_2025",
  "name": "Tax Authority Phishing Campaign Q1 2025",
  "attackCategory": "credential_harvest",
  "status": "active",
  "urlCount": 128,
  "avgRiskScore": 83.7,
  "domains": ["incometax.gov.in", "gst.gov.in"],
  "lastSeen": "2026-04-30T10:21:00Z"
}`}</pre>
              </div>

              <div style={{ border: '1px solid #E8EDEB', borderRadius: 10, padding: 12, background: '#FFF9F1' }}>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, color: '#1a1c1e' }}>url_edges</div>
                <pre style={{ margin: 0, fontSize: 12, color: '#6B4E13', whiteSpace: 'pre-wrap' }}>{`{
  "fromUrl": "https://secure-login-incometax.xyz/auth/verify",
  "toUrl": "https://gst-auth-update.top/kyc/verify",
  "strength": 0.79,
  "factors": [
    { "name": "vector_similarity", "value": 0.84 },
    { "name": "shared_attack_category", "value": 0.74 }
  ]
}`}</pre>
              </div>

              <div style={{ border: '1px solid #E8EDEB', borderRadius: 10, padding: 12, background: '#F5F6F7' }}>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, color: '#1a1c1e' }}>scan_rules / threat_logs</div>
                <pre style={{ margin: 0, fontSize: 12, color: '#3D4F58', whiteSpace: 'pre-wrap' }}>{`// scan_rules (singleton)
{
  "_id": "active_rules",
  "thresholds": { "block": 70, "review": 45 },
  "weights": { "vector": 0.30, "payload": 0.20, "dga": 0.20 }
}

// threat_logs (audit)
{
  "urlId": "...",
  "timestamp": "2026-04-30T10:23:00Z",
  "action": "blocked",
  "scanTier": "L3_FULL_PIPELINE",
  "aiConfidence": 0.94,
  "riskScore": 86.4
}`}</pre>
              </div>
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 18, color: '#1a1c1e' }}>
              Data Ingestion Source and Purpose Flow
            </h3>
            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['URL Scanner request', 'Incoming URL is enriched, scored, embedded, and upserted into urls as docType=scan.'],
                ['Threat intel seeding', 'Threat feed-style records are generated and stored in urls as docType=threat_intel for shared search/vector retrieval.'],
                ['Campaign detection', 'Vector neighbors + attack category + time-window logic create/update campaigns and tag matched URLs.'],
                ['Graph linking', 'Similarity evidence creates url_edges so related threats can be traversed as a connected graph.'],
                ['Rules and audit', 'scan_rules controls scoring behavior; threat_logs keeps operational action history for review.'],
              ].map(([title, detail]) => (
                <div key={title} style={{ background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px' }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#1a1c1e', marginBottom: 4 }}>{title}</div>
                  <div style={{ fontSize: 13, color: '#3D4F58', lineHeight: 1.5 }}>{detail}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 18, color: '#1a1c1e' }}>
              Embedding Strategy Used In This Solution
            </h3>
            <div style={{ display: 'grid', gap: 10, fontSize: 13, color: '#3D4F58', lineHeight: 1.55 }}>
              <div>
                <strong style={{ color: '#1a1c1e' }}>Base embedding input:</strong> Scanner builds <strong>summaryText</strong> from URL metadata + threat signals (domain age, DNS/hosting flags, structural risk, DGA/homoglyph signals, classification, risk score, payload types).
              </div>
              <div>
                <strong style={{ color: '#1a1c1e' }}>Model/runtime:</strong> Voyage API at <strong>ai.mongodb.com/v1/embeddings</strong> using <strong>voyage-4</strong>, producing a <strong>1024-dim</strong> vector stored in <strong>embedding</strong>.
              </div>
              <div>
                <strong style={{ color: '#1a1c1e' }}>Unified retrieval design:</strong> Both scan docs and threat-intel docs live in <strong>urls</strong> and share the same embedding field, enabling one vector query to retrieve both types.
              </div>
              <div>
                <strong style={{ color: '#1a1c1e' }}>Campaign re-embedding:</strong> After campaign detection, summaryText is rewritten with campaign context and re-embedded so future scans can resolve campaign semantics in a single query.
              </div>
              <div>
                <strong style={{ color: '#1a1c1e' }}>Why summary-based vectors:</strong> Embedding a compact natural-language summary of URL + metadata performs better than embedding only raw URL text for semantic threat similarity.
              </div>
            </div>
          </div>
        </div>
      )}

      {activeView === 'stack' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: 18, color: '#1a1c1e' }}>AI Models, Search Indexes, and Runtime Defaults</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <FeaturePill>Voyage Embeddings</FeaturePill>
                <FeaturePill bg="#F3EEFF" color="#4B2B91">Foundry LLM</FeaturePill>
                <FeaturePill bg="#E3FCF7" color="#0F5132">Atlas Search Stack</FeaturePill>
              </div>
            </div>

            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['Embedding model (runtime default)', 'voyage-4', 'Used by embedding service for URL and summary vectors.'],
                ['Embedding endpoint', 'https://ai.mongodb.com/v1/embeddings', 'Called with VOYAGE_AI_API_KEY for single and batch embedding generation.'],
                ['LLM model (runtime default)', 'gpt-5.4', 'Used in Foundry-backed agentic step to produce decision, confidence, reasoning, and score adjustment.'],
                ['LLM endpoint', 'GROVE_FOUNDRY_CHAT_URL', 'Foundry chat completions endpoint for classifier workflow.'],
                ['Atlas Search index', 'url_search_index', 'Lexical and fuzzy retrieval on url, domain, and summaryText.'],
                ['Vector Search index', 'url_vector_index', 'Semantic nearest-neighbor retrieval on embedding vectors.'],
                ['Hybrid retrieval', '$rankFusion', 'Weighted fusion of Atlas lexical and Vector semantic results.'],
                ['Vector dimensions / similarity', '1024 / cosine', 'Configured for semantic URL similarity retrieval in Atlas vector index.'],
              ].map(([name, value, purpose]) => (
                <div key={name} style={{ display: 'grid', gridTemplateColumns: '240px 180px 1fr', gap: 12, background: '#F9FAFB', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13 }}>
                  <div style={{ fontWeight: 700, color: '#3D4F58' }}>{name}</div>
                  <div style={{ color: '#1a1c1e', fontFamily: 'monospace' }}>{value}</div>
                  <div style={{ color: '#3D4F58' }}>{purpose}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 17, color: '#1a1c1e' }}>Frontend Module Stack</h3>
            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['App framework', 'Next.js 15 + React 18', 'Page routing, SSR/CSR composition, and app shell for analyst workflows.'],
                ['UI system', 'MongoDB LeafyGreen UI packages', 'Consistent enterprise components for tables, cards, forms, tabs, and notifications.'],
                ['Charts', 'Recharts', 'Risk breakdown, trend charts, and dashboard visualization panels.'],
                ['API client', 'Axios', 'Browser-side calls to backend /api/v1 routes.'],
                ['Linting', 'ESLint + eslint-config-next', 'Code quality and static checks in frontend module.'],
              ].map(([name, stack, purpose]) => (
                <div key={name} style={{ display: 'grid', gridTemplateColumns: '180px 250px 1fr', gap: 12, background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13 }}>
                  <div style={{ fontWeight: 700, color: '#3D4F58' }}>{name}</div>
                  <div style={{ color: '#1a1c1e', fontFamily: 'monospace' }}>{stack}</div>
                  <div style={{ color: '#3D4F58' }}>{purpose}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 17, color: '#1a1c1e' }}>Backend Module Stack</h3>
            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['API layer', 'FastAPI + Uvicorn + Pydantic', 'Defines REST endpoints, request validation, response typing, and ASGI runtime.'],
                ['Data layer', 'Motor (async MongoDB driver)', 'Repository pattern CRUD, aggregations, and index-aware querying.'],
                ['Config layer', 'python-dotenv + env vars', 'Loads runtime secrets and deployment config values.'],
                ['HTTP integration', 'httpx', 'Calls Voyage embedding API, Foundry LLM endpoint, and external enrichment APIs.'],
                ['URL scoring logic', 'Custom risk engine + python-Levenshtein', 'Threat scoring, typo-tolerant phishing keyword matching, and classification floors/thresholds.'],
                ['Enrichment DNS', 'dnspython', 'A/AAAA/CNAME/MX/NS/TXT lookups, DNSSEC check, reverse DNS.'],
                ['Enrichment WHOIS', 'python-whois', 'Domain age, registrar, privacy hints, expiry windows.'],
                ['Enrichment TLS', 'ssl + socket', 'Certificate type, issuer, domain-match, recency, and expiry risk signals.'],
                ['Testing', 'pytest + pytest-asyncio', 'Unit tests and async behavior validation in backend modules.'],
              ].map(([name, stack, purpose]) => (
                <div key={name} style={{ display: 'grid', gridTemplateColumns: '180px 250px 1fr', gap: 12, background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13 }}>
                  <div style={{ fontWeight: 700, color: '#3D4F58' }}>{name}</div>
                  <div style={{ color: '#1a1c1e', fontFamily: 'monospace' }}>{stack}</div>
                  <div style={{ color: '#3D4F58' }}>{purpose}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 17, color: '#1a1c1e' }}>Search + AI Module Purpose Map</h3>
            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['Atlas Search service', 'Lexical search, fuzzy typo tolerance, highlights, filters, and facets for analyst drill-down.'],
                ['Vector Search service', 'Embedding-based semantic retrieval of similar malicious URLs and threat-intel neighbors.'],
                ['Hybrid Search service', 'Combines Atlas and Vector pipelines through weighted $rankFusion scoring.'],
                ['Unified Search service', 'Orchestrates atlas/vector/hybrid calls and powers search demo scenarios.'],
                ['Embedding service', 'Creates single/batch embeddings for scan context and record enrichment.'],
                ['Agentic analysis service', 'Runs Foundry classifier workflow to add decision confidence and bounded score adjustment.'],
                ['Campaign detection service', 'Clusters related malicious URLs and links them into campaign-level intelligence.'],
                ['Campaign re-embedding flow', 'Regenerates vectors with campaign context so future semantic retrieval is stronger.'],
              ].map(([moduleName, purpose]) => (
                <div key={moduleName} style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 12, background: '#F9FAFB', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13 }}>
                  <div style={{ fontWeight: 700, color: '#3D4F58' }}>{moduleName}</div>
                  <div style={{ color: '#3D4F58', lineHeight: 1.5 }}>{purpose}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 17, color: '#1a1c1e' }}>Infrastructure and Delivery Stack</h3>
            <div style={{ display: 'grid', gap: 10 }}>
              {[
                ['Container runtime', 'Docker + Docker Compose', 'Runs frontend and backend locally as coordinated services.'],
                ['Backend packaging', 'Poetry', 'Dependency management and script execution for Python backend.'],
                ['Frontend packaging', 'npm', 'Dependency management and Next.js build/start tasks.'],
                ['Database platform', 'MongoDB Atlas', 'Persists URL records, threat intelligence, campaigns, and search/vector indexes.'],
              ].map(([name, stack, purpose]) => (
                <div key={name} style={{ display: 'grid', gridTemplateColumns: '180px 250px 1fr', gap: 12, background: '#F5F6F7', border: '1px solid #E8EDEB', borderRadius: 10, padding: '10px 12px', fontSize: 13 }}>
                  <div style={{ fontWeight: 700, color: '#3D4F58' }}>{name}</div>
                  <div style={{ color: '#1a1c1e', fontFamily: 'monospace' }}>{stack}</div>
                  <div style={{ color: '#3D4F58' }}>{purpose}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
