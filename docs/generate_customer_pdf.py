from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Preformatted, Paragraph, SimpleDocTemplate, Spacer

OUTPUT = "docs/ShieldNet_Customer_Brief.pdf"


def p(text):
    return Paragraph(text, styles["Body"])


def h(text):
    return Paragraph(text, styles["Heading"])


styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="Heading", parent=styles["Heading2"], fontSize=14, spaceAfter=8, textColor="#001E2B"))
styles.add(ParagraphStyle(name="Body", parent=styles["BodyText"], fontSize=10.5, leading=14))
styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=9.5, textColor="#3D4F58"))
styles.add(ParagraphStyle(name="MonoCode", fontName="Courier", fontSize=8.8, leading=11))


def main():
    doc = SimpleDocTemplate(OUTPUT, pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm)
    story = []

    story.append(Paragraph("ShieldNet AI: Customer Solution Brief", styles["Title"]))
    story.append(Paragraph("Version: April 2026", styles["Small"]))
    story.append(Spacer(1, 8))

    story.append(h("1. Executive Summary"))
    story.append(p("ShieldNet AI is a real-time malicious URL detection platform that combines deterministic analysis, semantic vector retrieval, Atlas text search, and optional Foundry-based agentic reasoning."))
    story.append(p("It helps security teams triage suspicious URLs faster with explainable evidence and campaign-level context."))

    story.append(h("2. Business Value"))
    story.append(p("- Accelerates URL triage through automated risk scoring and evidence cards.<br/>"
                   "- Improves detection quality using lexical + semantic retrieval.<br/>"
                   "- Supports campaign intelligence by clustering related malicious URLs.<br/>"
                   "- Enables analyst workflows using threat database filters and status operations."))

    story.append(h("3. High-Level Architecture"))
    story.append(p("Frontend: Next.js 15 + React 18 + Recharts"))
    story.append(p("Backend: FastAPI + Motor + Pydantic"))
    story.append(p("Data & Search: MongoDB Atlas (Atlas Search + Vector Search + Hybrid Rank Fusion)"))
    story.append(p("Embeddings: Voyage API (voyage-4 default, 1024 dimensions)"))
    story.append(p("Optional Agentic Layer: Microsoft Foundry (gpt-5.4 default)"))

    story.append(h("4. Key Functional Modules"))
    story.append(p("- URL Scanner: extraction, scoring, vector evidence, recommendation."))
    story.append(p("- Threat Database: searchable repository with operational triage."))
    story.append(p("- Search Playground: Atlas vs Vector vs Hybrid comparison."))
    story.append(p("- Campaign Detection: groups related threats and tags URLs."))
    story.append(p("- Rules Management: active threshold and weight configuration."))
    story.append(p("- URL Graph: relation edges between similar threats."))

    story.append(h("5. Data Sources and Ingestion"))
    story.append(p("- Live scan ingestion writes/updates records in urls collection."))
    story.append(p("- Threat-intel seed writes threat docs into urls using docType=threat_intel."))
    story.append(p("- Campaign detection writes campaign aggregates in campaigns."))
    story.append(p("- Similarity graph writes edges into url_edges."))
    story.append(p("- Active policy config is maintained in scan_rules."))

    story.append(h("6. Sample Schemas"))

    urls_scan = '''{
  "url": "https://secure-login-incometax.xyz/auth/verify",
  "domain": "secure-login-incometax.xyz",
  "canonicalDomain": "incometax.gov.in",
  "docType": "scan",
  "threatClassification": "phishing",
  "riskScore": 86.4,
  "status": "blocked",
  "summaryText": "Credential harvest style URL impersonating tax portal...",
  "embedding": ["1024-dim vector"],
  "payloadTypes": ["credential_harvest", "open_redirect"],
  "campaignId": "campaign_001_tax_auth_2025",
  "scanCount": 3,
  "firstSeenAt": "2026-04-27T08:51:00Z",
  "lastSeenAt": "2026-04-30T11:08:12Z"
}'''
    story.append(p("6.1 urls (scan record)"))
    story.append(Preformatted(urls_scan, styles["MonoCode"]))

    urls_intel = '''{
  "url": "https://nic.in/login?redirect=http://gov-login-verify.xyz/capture",
  "domain": "nic.in",
  "docType": "threat_intel",
  "threatClassification": "phishing",
  "attackCategory": "open_redirect",
  "feedName": "CERT-IN_Feed",
  "summaryText": "Open redirect attack against nic.in ...",
  "embedding": ["1024-dim vector"]
}'''
    story.append(p("6.2 urls (threat-intel record in same collection)"))
    story.append(Preformatted(urls_intel, styles["MonoCode"]))

    campaigns = '''{
  "campaignId": "campaign_001_tax_auth_2025",
  "name": "Tax Authority Phishing Campaign Q1 2025",
  "attackCategory": "credential_harvest",
  "status": "active",
  "urlCount": 128,
  "avgRiskScore": 83.7,
  "domains": ["incometax.gov.in", "gst.gov.in"],
  "lastSeen": "2026-04-30T10:21:00Z"
}'''
    story.append(p("6.3 campaigns"))
    story.append(Preformatted(campaigns, styles["MonoCode"]))

    edges = '''{
  "fromUrl": "https://secure-login-incometax.xyz/auth/verify",
  "toUrl": "https://gst-auth-update.top/kyc/verify",
  "strength": 0.79,
  "factors": [
    {"name": "vector_similarity", "value": 0.84},
    {"name": "shared_attack_category", "value": 0.74}
  ]
}'''
    story.append(p("6.4 url_edges"))
    story.append(Preformatted(edges, styles["MonoCode"]))

    rules = '''{
  "_id": "active_rules",
  "thresholds": {"block": 70, "review": 45},
  "weights": {"vector": 0.30, "payload": 0.20, "dga": 0.20}
}'''
    story.append(p("6.5 scan_rules"))
    story.append(Preformatted(rules, styles["MonoCode"]))

    story.append(h("7. Embedding Strategy"))
    story.append(p("- Embed summaryText (URL + metadata + threat signals), not raw URL alone."))
    story.append(p("- Default model: voyage-4; vector size: 1024; similarity: cosine."))
    story.append(p("- Campaign-aware re-embedding improves future threat/campaign retrieval precision."))

    story.append(h("8. Detection Flow"))
    story.append(p("1) Input URL -> 2) Feature extraction -> 3) Summary + embedding -> 4) Vector search -> 5) Risk engine -> 6) Campaign tag/update -> 7) Persist + response"))

    story.append(h("9. Operational Notes"))
    story.append(p("- This is a validation/demo deployment and should be calibrated for production traffic."))
    story.append(p("- Keep secrets in environment variables and enforce role-based access on rules/status overrides."))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Prepared for customer sharing. Customize with project branding, SLAs, and rollout plan.", styles["Small"]))

    doc.build(story)


if __name__ == "__main__":
    main()
