"""Evaluate minimal fixed-format UC dataset accuracy (UC01-UC25).

Runs scans against /api/v1/scan for curated use-case inputs and reports
per-case pass/fail plus aggregate accuracy.

Usage:
    cd backend
    poetry run python -m scripts.eval_minimal_usecase_accuracy
    poetry run python -m scripts.eval_minimal_usecase_accuracy --api-url http://localhost:8000
"""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime

import httpx


CASES = [
    {"ucId": "UC01", "name": "Typosquatting", "url": "https://sbi-secure-login.com/verify", "expected": "phishing"},
    {"ucId": "UC02", "name": "Phishing URL Identification", "url": "https://secure-hdfc-banking.in/netbanking/login", "expected": "phishing"},
    {"ucId": "UC03", "name": "Threat Intel Feed Match", "url": "https://login-microsoft365-verify.com/auth", "expected": "phishing"},
    {"ucId": "UC04", "name": "Government Impersonation", "url": "https://aadhaar-update-portal.in/ekyc", "expected": "phishing"},
    {"ucId": "UC05", "name": "Homoglyph / IDN Attack", "url": "https://xn--gogle-mra.com/login", "expected": "phishing"},
    {"ucId": "UC06", "name": "Shortener Abuse", "url": "https://bit.ly/3xR7kQm", "expected": "phishing"},
    {"ucId": "UC07", "name": "Brand Impersonation", "url": "https://icici-bank-rewards.com/claim", "expected": "phishing"},
    {"ucId": "UC08", "name": "Malware Distribution", "url": "https://free-software-download.xyz/adobe-reader-update.exe", "expected": "malware"},
    {
        "ucId": "UC09",
        "name": "Hindi Banking Scam",
        "url": "https://sbi-kyc-update.in/verify",
        "pageContent": "प्रिय ग्राहक, आपका SBI खाता ब्लॉक हो गया है। तुरंत KYC अपडेट करें अन्यथा 24 घंटे में खाता बंद कर दिया जाएगा।",
        "expected": "phishing",
    },
    {
        "ucId": "UC10",
        "name": "Tamil EPFO Scam",
        "url": "https://epfo-claim-status.in/check",
        "pageContent": "உங்கள் EPFO கணக்கில் ₹15,000 நிலுவை உள்ளது. இப்போதே பெற கீழே உள்ள இணைப்பை கிளிக் செய்யவும்.",
        "expected": "phishing",
    },
    {
        "ucId": "UC11",
        "name": "Bengali PM-KISAN Scam",
        "url": "https://pm-kisan-samman.in/apply",
        "pageContent": "প্রিয় কৃষক, আপনার PM-KISAN ₹6000 জমা হয়েছে। এখনই নিন এবং আধার নম্বর দিন।",
        "expected": "phishing",
    },
    {
        "ucId": "UC12",
        "name": "Hindi PAN-Aadhaar Scam",
        "url": "https://aadhaar-link-pan.in/update",
        "pageContent": "आयकर विभाग: आपका PAN आधार से लिंक नहीं है। तुरंत लिंक करें अन्यथा PAN निष्क्रिय हो जाएगा।",
        "expected": "phishing",
    },
    {"ucId": "UC13", "name": "Visual Baseline SBI", "url": "https://onlinesbi.sbi", "expected": "benign"},
    {"ucId": "UC14", "name": "Visual Clone SBI", "url": "https://sbi-secure-login.com/verify", "expected": "phishing"},
    {"ucId": "UC15", "name": "Visual Baseline HDFC", "url": "https://hdfcbank.com", "expected": "benign"},
    {"ucId": "UC16", "name": "Visual Clone HDFC", "url": "https://secure-hdfc-banking.in/netbanking/login", "expected": "phishing"},
    {"ucId": "UC17", "name": "Gov Portal Baseline", "url": "https://eprocure.gov.in", "expected": "benign"},
    {
        "ucId": "UC18",
        "name": "Watering Hole Variant",
        "url": "https://eprocure.gov.in?variant=compromised",
        "pageContent": "Compromised page variant with hidden script injection from supply-chain source.",
        "expected": "suspicious",
    },
    {"ucId": "UC19", "name": "Known Phish Host", "url": "https://sbi-secure-login.com/verify", "expected": "phishing"},
    {"ucId": "UC20", "name": "Redirect Chain Infrastructure", "url": "https://click-track-offer.com", "expected": "suspicious"},
    {"ucId": "UC21", "name": "TLS Anomaly", "url": "https://secure-banking-portal.xyz", "expected": "suspicious"},
    {"ucId": "UC22", "name": "Fast-Flux Botnet", "url": "https://fast-flux-botnet.top", "expected": "c2"},
    {"ucId": "UC23", "name": "Fast-Flux Variant", "url": "https://update-service-cdn.buzz", "expected": "malware"},
    {"ucId": "UC24", "name": "Supply Chain CDN", "url": "https://cdn-analytics-lib.com/tracker.js", "expected": "malware"},
    {"ucId": "UC25", "name": "Behavior Anomaly", "url": "https://sbi-secure-login.com/verify", "expected": "phishing"},
]


async def scan_case(client: httpx.AsyncClient, api_url: str, case: dict) -> dict:
    payload = {"url": case["url"]}
    if case.get("pageContent"):
        payload["pageContent"] = case["pageContent"]

    try:
        response = await client.post(f"{api_url}/api/v1/scan", json=payload, timeout=30.0)
        response.raise_for_status()
        data = response.json()
        predicted = (
            data.get("urlRecord", {}).get("threatClassification")
            or data.get("threatClassification")
            or "benign"
        )
        return {
            "ucId": case["ucId"],
            "name": case["name"],
            "url": case["url"],
            "expected": case["expected"],
            "predicted": predicted,
            "status": data.get("urlRecord", {}).get("status") or data.get("status"),
            "riskScore": data.get("urlRecord", {}).get("riskScore") or data.get("riskScore"),
            "match": predicted == case["expected"],
            "error": None,
        }
    except Exception as exc:
        return {
            "ucId": case["ucId"],
            "name": case["name"],
            "url": case["url"],
            "expected": case["expected"],
            "predicted": "error",
            "status": None,
            "riskScore": None,
            "match": False,
            "error": str(exc),
        }


async def evaluate(api_url: str) -> dict:
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[scan_case(client, api_url, c) for c in CASES])

    total = len(results)
    errors = sum(1 for r in results if r["error"])
    success = total - errors
    passed = sum(1 for r in results if r["match"])
    accuracy = (passed / total) if total else 0.0

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "apiUrl": api_url,
        "total": total,
        "success": success,
        "errors": errors,
        "passed": passed,
        "accuracy": accuracy,
        "results": results,
    }


def print_report(report: dict):
    print("=" * 88)
    print("MINIMAL UC ACCURACY REPORT")
    print("=" * 88)
    print(f"API URL       : {report['apiUrl']}")
    print(f"Total cases   : {report['total']}")
    print(f"Successful    : {report['success']}")
    print(f"Errors        : {report['errors']}")
    print(f"Passed        : {report['passed']}")
    print(f"Accuracy      : {report['accuracy'] * 100:.2f}%")
    print("-" * 88)
    for r in report["results"]:
        flag = "PASS" if r["match"] else "FAIL"
        if r["error"]:
            flag = "ERROR"
        print(
            f"{r['ucId']:>4} | {flag:>5} | exp={r['expected']:<10} pred={r['predicted']:<10} "
            f"risk={str(r['riskScore']):<6} | {r['name']}"
        )
    print("=" * 88)


async def main():
    parser = argparse.ArgumentParser(description="Evaluate minimal UC dataset accuracy")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Backend API URL")
    parser.add_argument("--output", default="minimal_uc_accuracy.json", help="Output JSON file")
    args = parser.parse_args()

    report = await evaluate(args.api_url.rstrip("/"))
    print_report(report)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(f"Saved report: {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
