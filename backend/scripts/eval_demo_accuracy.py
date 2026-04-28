"""
Benchmark evaluation script for demo accuracy measurement.

Evaluates the URL scanner against a fixed set of ground-truth labels,
calculating precision, recall, F1-score, and confusion matrix.

Usage:
    poetry run python -m scripts.eval_demo_accuracy
    poetry run python -m scripts.eval_demo_accuracy --output results.json
    poetry run python -m scripts.eval_demo_accuracy --api-url http://localhost:8000
"""

import asyncio
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

import httpx

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Ground-truth benchmark dataset: URL -> expected threatClassification (or None for benign)
BENCHMARK_URLS: Dict[str, str | None] = {
    # Benign domains (expected: None / benign)
    "google.com": None,
    "www.google.com": None,
    "github.com": None,
    "stackoverflow.com": None,
    "mozilla.org": None,
    "wikipedia.org": None,
    "openai.com": None,
    "microsoft.com": None,
    "amazon.com": None,
    "apple.com": None,
    "facebook.com": None,
    "twitter.com": None,
    "linkedin.com": None,
    "reddit.com": None,
    "medium.com": None,
    "docker.com": None,
    "kubernetes.io": None,
    "nginx.org": None,
    "apache.org": None,
    "python.org": None,

    # Phishing URLs (expected: phishing)
    "g00gle-verify.com": "phishing",  # Homoglyph/lookalike
    "secure-paypal-confirm.com": "phishing",  # Common phishing pattern
    "amazon-account-update.net": "phishing",  # Fake update
    "apple-id-confirm.co": "phishing",  # ID confirmation phishing
    "fb-login-verify.tk": "phishing",  # Facebook phishing
    "microsoft-security-update.info": "phishing",  # Security alert phishing
    "googleaccounts-recovery.xyz": "phishing",  # Account recovery phishing
    "linkedin-job-offer.tk": "phishing",  # Job offer phishing
    "wellsfargo-verify-account.net": "phishing",  # Banking phishing
    "paypal-resolution-center.com": "phishing",  # PayPal clone

    # Malware URLs (expected: malware)
    "malware-distribution-site.net": "malware",
    "suspicious-executable-download.tk": "malware",
    "ransomware-command-and-control.ru": "malware",
    "malicious-file-host.xyz": "malware",
    "trojan-dropper.info": "malware",
    "botnet-c2-server.net": "malware",
    "exploit-kit-payload.tk": "malware",
    "worm-distribution.xyz": "malware",
    "spyware-installer.info": "malware",
    "adware-pusher.net": "malware",

    # C2 (Command and Control) URLs (expected: c2)
    "c2-botnet-panel.tk": "c2",
    "command-control-server.ru": "c2",
    "botnet-command-center.net": "c2",
    "attacker-infrastructure.xyz": "c2",
    "malware-c2-communication.info": "c2",
    "underground-c2-panel.tk": "c2",
    "remote-access-trojan-c2.xyz": "c2",
    "apt-command-center.ru": "c2",
    "ransomware-negotiation-site.net": "c2",
    "dga-sink-domain.tk": "c2",

    # Suspicious URLs (expected: suspicious)
    "slightly-suspicious-domain.tk": "suspicious",
    "looks-like-phishing.net": "suspicious",
    "potential-scam-site.info": "suspicious",
    "questionable-business.xyz": "suspicious",
    "unclear-legitimacy.tk": "suspicious",
    "possibly-malicious.net": "suspicious",
    "high-risk-content.info": "suspicious",
    "unverified-service.xyz": "suspicious",
    "risky-download-site.tk": "suspicious",
    "suspicious-redirect-farm.net": "suspicious",

    # Homoglyph/lookalike domains (typically phishing)
    "g0ogle.com": "phishing",  # Zero instead of O
    "am4zon.com": "phishing",  # 4 instead of A
    "appl3.com": "phishing",  # 3 instead of E
    "facebook-security.net": "phishing",  # Not official
    "linkedin-update.tk": "phishing",  # Not official

    # Additional benign control samples
    "example.com": None,
    "test.com": None,
    "demo.com": None,
    "localhost": None,
    "127.0.0.1": None,
}


async def scan_url(client: httpx.AsyncClient, url: str, api_url: str) -> Dict:
    """Scan a URL via the backend API."""
    try:
        scan_payload = {"url": url}
        resp = await client.post(
            f"{api_url}/api/v1/scan",
            json=scan_payload,
            timeout=30.0
        )
        if resp.status_code == 200:
            data = resp.json()
            return data
        else:
            logger.warning(f"Scan failed for {url}: HTTP {resp.status_code}")
            return {"error": f"HTTP {resp.status_code}", "url": url}
    except asyncio.TimeoutError:
        logger.warning(f"Scan timeout for {url}")
        return {"error": "timeout", "url": url}
    except Exception as e:
        logger.warning(f"Scan error for {url}: {e}")
        return {"error": str(e), "url": url}


async def evaluate_accuracy(
    api_url: str = "http://localhost:8000",
    output_file: str | None = None,
    limit: int | None = None
) -> Dict:
    """
    Evaluate scanner accuracy against benchmark URLs.

    Args:
        api_url: Backend API URL
        output_file: Optional file to write JSON results
        limit: Limit evaluation to N URLs (for quick testing)

    Returns:
        Dictionary with metrics (precision, recall, F1, confusion matrix, etc.)
    """
    test_urls = list(BENCHMARK_URLS.items())
    if limit:
        test_urls = test_urls[:limit]

    logger.info(f"Starting accuracy evaluation on {len(test_urls)} benchmark URLs")
    logger.info(f"API endpoint: {api_url}")

    # Initialize metrics collection
    predictions = []
    ground_truths = []
    errors = []
    class_labels = {"benign", "phishing", "malware", "c2", "suspicious"}

    # Run scans
    async with httpx.AsyncClient() as client:
        tasks = [scan_url(client, url, api_url) for url, _ in test_urls]
        results = await asyncio.gather(*tasks)

    # Process results
    for (url, expected), scan_result in zip(test_urls, results):
        if "error" in scan_result:
            errors.append({"url": url, "error": scan_result["error"]})
            continue

        # Determine predicted class
        threat_class = scan_result.get("threatClassification") or "benign"
        status = scan_result.get("status")

        # Normalize: treat "allowed" status as benign
        if status == "allowed" and threat_class == "benign":
            predicted = "benign"
        elif threat_class in class_labels:
            predicted = threat_class
        else:
            predicted = "benign"

        # Normalize expected (None -> "benign")
        expected_norm = expected or "benign"

        predictions.append(predicted)
        ground_truths.append(expected_norm)

        logger.debug(
            f"URL: {url:40s} | Expected: {expected_norm:12s} | "
            f"Predicted: {predicted:12s} | Risk: {scan_result.get('riskScore', 0):.1f}"
        )

    # Calculate metrics
    metrics = calculate_metrics(ground_truths, predictions, class_labels)
    metrics["benchmark_size"] = len(test_urls)
    metrics["scan_success"] = len(test_urls) - len(errors)
    metrics["scan_errors"] = len(errors)
    metrics["timestamp"] = datetime.utcnow().isoformat()

    # Build detailed results
    results_data = {
        "metrics": metrics,
        "errors": errors,
        "eval_date": datetime.utcnow().isoformat(),
        "api_url": api_url,
        "benchmark_urls_count": len(test_urls),
    }

    # Log summary
    logger.info("\n" + "=" * 80)
    logger.info("ACCURACY EVALUATION RESULTS")
    logger.info("=" * 80)
    logger.info(f"Benchmark URLs: {metrics['benchmark_size']}")
    logger.info(f"Successful scans: {metrics['scan_success']}")
    logger.info(f"Failed scans: {metrics['scan_errors']}")
    logger.info("")
    logger.info("Overall Metrics:")
    logger.info(f"  Accuracy:  {metrics['overall_accuracy']:.4f} ({metrics['overall_accuracy']*100:.2f}%)")
    logger.info(f"  Precision: {metrics['overall_precision']:.4f}")
    logger.info(f"  Recall:    {metrics['overall_recall']:.4f}")
    logger.info(f"  F1-Score:  {metrics['overall_f1']:.4f}")
    logger.info("")

    if metrics.get("per_class_metrics"):
        logger.info("Per-Class Metrics:")
        for class_label in sorted(class_labels):
            if class_label in metrics["per_class_metrics"]:
                cm = metrics["per_class_metrics"][class_label]
                logger.info(f"  {class_label}:")
                logger.info(f"    Precision: {cm['precision']:.4f}")
                logger.info(f"    Recall:    {cm['recall']:.4f}")
                logger.info(f"    F1-Score:  {cm['f1']:.4f}")
                logger.info(f"    Support:   {cm['support']}")

    logger.info("")
    if metrics.get("confusion_matrix"):
        logger.info("Confusion Matrix:")
        cm = metrics["confusion_matrix"]
        logger.info(f"  {json.dumps(cm, indent=4)}")

    if errors:
        logger.info("")
        logger.info(f"Errors ({len(errors)}):")
        for error in errors[:10]:  # Show first 10
            logger.info(f"  {error['url']}: {error['error']}")

    logger.info("=" * 80 + "\n")

    # Optionally save to file
    if output_file:
        with open(output_file, "w") as f:
            json.dump(results_data, f, indent=2)
        logger.info(f"Results saved to {output_file}")

    return results_data


def calculate_metrics(ground_truths: List[str], predictions: List[str], class_labels) -> Dict:
    """
    Calculate precision, recall, F1, accuracy, and confusion matrix.

    Args:
        ground_truths: List of ground truth labels
        predictions: List of predicted labels
        class_labels: Set of possible class labels

    Returns:
        Dictionary with calculated metrics
    """
    metrics = {}

    # Overall accuracy
    correct = sum(1 for gt, pred in zip(ground_truths, predictions) if gt == pred)
    total = len(ground_truths)
    metrics["overall_accuracy"] = correct / total if total > 0 else 0

    # Per-class metrics and confusion matrix
    per_class = {}
    confusion_matrix = defaultdict(lambda: defaultdict(int))

    for gt, pred in zip(ground_truths, predictions):
        confusion_matrix[gt][pred] += 1

    # Calculate per-class metrics
    overall_tp, overall_fp, overall_fn = 0, 0, 0

    for class_label in sorted(class_labels):
        tp = confusion_matrix[class_label].get(class_label, 0)
        fp = sum(confusion_matrix[other][class_label]
                 for other in class_labels if other != class_label)
        fn = sum(confusion_matrix[class_label][other]
                 for other in class_labels if other != class_label)
        support = tp + fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        per_class[class_label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }

        overall_tp += tp
        overall_fp += fp
        overall_fn += fn

    metrics["per_class_metrics"] = per_class

    # Overall precision/recall (macro)
    if per_class:
        metrics["overall_precision"] = sum(
            m["precision"] for m in per_class.values()
        ) / len(per_class)
        metrics["overall_recall"] = sum(
            m["recall"] for m in per_class.values()
        ) / len(per_class)
        metrics["overall_f1"] = sum(
            m["f1"] for m in per_class.values()
        ) / len(per_class)
    else:
        metrics["overall_precision"] = 0
        metrics["overall_recall"] = 0
        metrics["overall_f1"] = 0

    # Confusion matrix as dict (for JSON serialization)
    metrics["confusion_matrix"] = {
        true_label: dict(confusion_matrix[true_label])
        for true_label in sorted(class_labels)
    }

    return metrics


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Evaluate URL scanner accuracy on benchmark dataset"
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="Backend API URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file for JSON results (optional)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit to N URLs (optional, for quick testing)"
    )

    args = parser.parse_args()

    # Run evaluation
    results = asyncio.run(evaluate_accuracy(
        api_url=args.api_url,
        output_file=args.output,
        limit=args.limit,
    ))

    return results


if __name__ == "__main__":
    main()
