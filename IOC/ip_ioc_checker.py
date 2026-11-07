
import os
import re
import csv
import json
import hashlib
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIG
# ============================================================

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
HA_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
MB_AUTH_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

os.makedirs(OUTPUT_DIR, exist_ok=True)

TIMEOUT = 30

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "FIN-WS-047-LAB-IOC-CHECKER/1.0"
})


# ============================================================
# GENERAL HELPERS
# ============================================================

def api_request(method, url, **kwargs):
    try:
        response = SESSION.request(
            method,
            url,
            timeout=TIMEOUT,
            **kwargs
        )

        if response.status_code == 404:
            return {
                "status": "no_hit",
                "message": "IOC not found"
            }

        response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            data = {"raw_response": response.text[:1000]}

        return {
            "status": "ok",
            "data": data
        }

    except requests.exceptions.Timeout:
        return {
            "status": "error",
            "error": "Request timeout"
        }

    except requests.exceptions.HTTPError as exc:
        response = exc.response
        detail = response.text[:500] if response is not None else str(exc)

        return {
            "status": "error",
            "error": f"HTTP {response.status_code if response is not None else 'unknown'}: {detail}"
        }

    except requests.exceptions.RequestException as exc:
        return {
            "status": "error",
            "error": str(exc)
        }


def skipped(reason):
    return {
        "status": "skipped",
        "reason": reason
    }


def get_verdict(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        return "malicious"

    if suspicious > 0:
        return "suspicious"

    return "clean"


def normalize_domain(value):
    value = value.strip().lower()

    if "://" in value:
        value = urlparse(value).hostname or ""

    value = value.split("/")[0].split(":")[0].strip(".")

    if not value or len(value) > 253:
        return None

    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    if not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        value
    ):
        return None

    return value


def validate_hash(value):
    value = value.strip().lower()

    lengths = {
        32: "MD5",
        40: "SHA1",
        64: "SHA256"
    }

    if len(value) not in lengths:
        return None

    if not re.fullmatch(r"[a-f0-9]+", value):
        return None

    return {
        "hash": value,
        "type": lengths[len(value)]
    }


# ============================================================
# VIRUSTOTAL - FILE HASH
# ============================================================

def vt_check_hash(file_hash):
    if not VT_API_KEY:
        return skipped("VirusTotal API key not configured")

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    result = api_request("GET", url, headers=headers)

    if result["status"] != "ok":
        return result

    attributes = result["data"].get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "status": "ok",
        "sha256": attributes.get("sha256"),
        "sha1": attributes.get("sha1"),
        "md5": attributes.get("md5"),
        "file_name": attributes.get("meaningful_name"),
        "file_type": attributes.get("type_description"),
        "file_size": attributes.get("size"),
        "reputation": attributes.get("reputation"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "first_submission": attributes.get("first_submission_date"),
        "last_analysis": attributes.get("last_analysis_date"),
        "verdict": get_verdict(stats)
    }


# ============================================================
# HYBRID ANALYSIS - FILE HASH
# ============================================================

def ha_check_hash(file_hash):
    if not HA_API_KEY:
        return skipped("Hybrid Analysis API key not configured")

    url = "https://hybrid-analysis.com/api/v2/search/hash"

    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json"
    }

    result = api_request(
        "GET",
        url,
        headers=headers,
        params={"hash": file_hash}
    )

    if result["status"] != "ok":
        return result

    data = result["data"]

    if isinstance(data, dict):
        reports = data.get("result", data.get("data", []))
    elif isinstance(data, list):
        reports = data
    else:
        reports = []

    if not isinstance(reports, list):
        reports = []

    matches = []

    for report in reports:
        if not isinstance(report, dict):
            continue

        matches.append({
            "verdict": report.get("verdict"),
            "threat_score": report.get("threat_score"),
            "threat_level": report.get("threat_level"),
            "av_detect": report.get("av_detect"),
            "malware_family": report.get("vx_family"),
            "sha256": report.get("sha256"),
            "file_name": report.get("submit_name"),
            "analysis_start_time": report.get("analysis_start_time"),
            "job_id": report.get("job_id")
        })

    verdicts = [
        str(item.get("verdict", "")).lower()
        for item in matches
    ]

    if any(v == "malicious" for v in verdicts):
        verdict = "malicious"
    elif any(v == "suspicious" for v in verdicts):
        verdict = "suspicious"
    elif matches:
        verdict = "no_malicious_verdict"
    else:
        verdict = "no_hit"

    return {
        "status": "ok",
        "total_matches": len(matches),
        "verdict": verdict,
        "matches": matches
    }


# ============================================================
# MALWAREBAZAAR - FILE HASH
# ============================================================

def mb_check_hash(file_hash):
    if not MB_AUTH_KEY:
        return skipped("MalwareBazaar Auth-Key not configured")

    url = "https://mb-api.abuse.ch/api/v1/"

    headers = {
        "Auth-Key": MB_AUTH_KEY,
        "Accept": "application/json"
    }

    result = api_request(
        "POST",
        url,
        headers=headers,
        data={
            "query": "get_info",
            "hash": file_hash
        }
    )

    if result["status"] != "ok":
        return result

    data = result["data"]

    if data.get("query_status") == "hash_not_found":
        return {
            "status": "ok",
            "verdict": "no_hit",
            "message": "Hash not found in MalwareBazaar"
        }

    if data.get("query_status") != "ok":
        return {
            "status": "error",
            "error": f"MalwareBazaar response: {data.get('query_status')}"
        }

    samples = data.get("data", [])

    if not samples:
        return {
            "status": "ok",
            "verdict": "no_hit",
            "message": "No sample information returned"
        }

    sample = samples[0]

    return {
        "status": "ok",
        "verdict": "malicious",
        "sha256": sample.get("sha256_hash"),
        "sha1": sample.get("sha1_hash"),
        "md5": sample.get("md5_hash"),
        "file_name": sample.get("file_name"),
        "file_type": sample.get("file_type"),
        "signature": sample.get("signature"),
        "file_size": sample.get("file_size"),
        "first_seen": sample.get("first_seen"),
        "last_seen": sample.get("last_seen"),
        "tags": sample.get("tags")
    }


# ============================================================
# VIRUSTOTAL - DOMAIN
# ============================================================

def vt_check_domain(domain):
    if not VT_API_KEY:
        return skipped("VirusTotal API key not configured")

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    result = api_request("GET", url, headers=headers)

    if result["status"] != "ok":
        return result

    attributes = result["data"].get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "status": "ok",
        "domain": domain,
        "registrar": attributes.get("registrar"),
        "creation_date": attributes.get("creation_date"),
        "reputation": attributes.get("reputation"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "categories": attributes.get("categories"),
        "last_analysis": attributes.get("last_analysis_date"),
        "verdict": get_verdict(stats)
    }


# ============================================================
# HYBRID ANALYSIS - DOMAIN
# ============================================================

def ha_check_domain(domain):
    if not HA_API_KEY:
        return skipped("Hybrid Analysis API key not configured")

    url = "https://hybrid-analysis.com/api/v2/search/terms"

    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    result = api_request(
        "POST",
        url,
        headers=headers,
        data={"domain": domain}
    )

    if result["status"] != "ok":
        return result

    data = result["data"]

    if isinstance(data, list):
        reports = data
    elif isinstance(data, dict):
        reports = data.get("result", data.get("data", []))
    else:
        reports = []

    if not isinstance(reports, list):
        reports = []

    matches = []

    for report in reports:
        if not isinstance(report, dict):
            continue

        matches.append({
            "verdict": report.get("verdict"),
            "threat_score": report.get("threat_score"),
            "malware_family": report.get("vx_family"),
            "sha256": report.get("sha256"),
            "file_name": report.get("submit_name"),
            "analysis_start_time": report.get("analysis_start_time"),
            "job_id": report.get("job_id"),
            "domains": report.get("domains", []),
            "hosts": report.get("hosts", [])
        })

    verdicts = [
        str(item.get("verdict", "")).lower()
        for item in matches
    ]

    if any(v == "malicious" for v in verdicts):
        verdict = "malicious"
    elif any(v == "suspicious" for v in verdicts):
        verdict = "suspicious"
    elif matches:
        verdict = "no_malicious_verdict"
    else:
        verdict = "no_hit"

    return {
        "status": "ok",
        "total_matches": len(matches),
        "verdict": verdict,
        "matches": matches
    }


# ============================================================
# URLHAUS - DOMAIN / HOST
# ============================================================

def urlhaus_check_domain(domain):
    if not URLHAUS_AUTH_KEY:
        return skipped("URLhaus Auth-Key not configured")

    url = "https://urlhaus-api.abuse.ch/v1/host/"

    headers = {
        "Auth-Key": URLHAUS_AUTH_KEY,
        "Accept": "application/json"
    }

    result = api_request(
        "POST",
        url,
        headers=headers,
        data={"host": domain}
    )

    if result["status"] != "ok":
        return result

    data = result["data"]

    query_status = data.get("query_status")

    if query_status == "no_results":
        return {
            "status": "ok",
            "domain": domain,
            "verdict": "no_hit",
            "total_urls": 0
        }

    if query_status != "ok":
        return {
            "status": "error",
            "error": f"URLhaus response: {query_status}"
        }

    urls = data.get("urls", [])

    return {
        "status": "ok",
        "domain": domain,
        "verdict": "malicious" if urls else "no_hit",
        "total_urls": len(urls),
        "blacklists": data.get("blacklists"),
        "urls": [
            {
                "url": item.get("url"),
                "url_status": item.get("url_status"),
                "threat": item.get("threat"),
                "date_added": item.get("date_added"),
                "tags": item.get("tags")
            }
            for item in urls[:20]
        ]
    }


# ============================================================
# OVERALL VERDICT
# ============================================================

def calculate_overall(results):
    malicious = False
    suspicious = False
    error = False

    for provider, result in results.items():
        status = result.get("status")
        verdict = str(result.get("verdict", "")).lower()

        if status == "error":
            error = True
        elif status == "ok":
            if verdict == "malicious":
                malicious = True
            elif verdict == "suspicious":
                suspicious = True

    if malicious:
        return "MALICIOUS"

    if suspicious:
        return "SUSPICIOUS"

    if error:
        return "INCONCLUSIVE"

    return "NO_MALICIOUS_HIT"


# ============================================================
# CHECK HASH
# ============================================================

def check_hash(item):
    file_hash = item["hash"]

    print(f"\n[*] Checking {item['type']}: {file_hash}")

    results = {
        "VirusTotal": vt_check_hash(file_hash),
        "HybridAnalysis": ha_check_hash(file_hash),
        "MalwareBazaar": mb_check_hash(file_hash)
    }

    for provider, result in results.items():
        status = result.get("status")

        if status == "ok":
            print(
                f"  - {provider}: OK | "
                f"{result.get('verdict', 'information available')}"
            )
        elif status == "skipped":
            print(f"  - {provider}: SKIPPED | {result.get('reason')}")
        else:
            print(
                f"  - {provider}: "
                f"{'NO HIT' if status == 'no_hit' else 'ERROR'} | "
                f"{result.get('error', result.get('message', ''))}"
            )

    overall = calculate_overall(results)
    print(f"\n  => Overall: {overall}")

    return {
        "ioc_type": "FILE_HASH",
        "hash_type": item["type"],
        "ioc": file_hash,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "overall_verdict": overall,
        "results": results
    }


# ============================================================
# CHECK DOMAIN
# ============================================================

def check_domain(domain):
    print(f"\n[*] Checking DOMAIN: {domain}")

    results = {
        "VirusTotal": vt_check_domain(domain),
        "HybridAnalysis": ha_check_domain(domain),
        "URLhaus": urlhaus_check_domain(domain)
    }

    for provider, result in results.items():
        status = result.get("status")

        if status == "ok":
            print(
                f"  - {provider}: OK | "
                f"{result.get('verdict', 'information available')}"
            )
        elif status == "skipped":
            print(f"  - {provider}: SKIPPED | {result.get('reason')}")
        else:
            print(
                f"  - {provider}: "
                f"{'NO HIT' if status == 'no_hit' else 'ERROR'} | "
                f"{result.get('error', result.get('message', ''))}"
            )

    overall = calculate_overall(results)
    print(f"\n  => Overall: {overall}")

    return {
        "ioc_type": "DOMAIN",
        "ioc": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "overall_verdict": overall,
        "results": results
    }


# ============================================================
# SAVE JSON / CSV
# ============================================================

def save_results(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(
        OUTPUT_DIR,
        f"hash_domain_enrichment_{timestamp}.json"
    )

    csv_path = os.path.join(
        OUTPUT_DIR,
        f"hash_domain_enrichment_{timestamp}.csv"
    )

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)

    rows = []

    for item in results:
        row = {
            "IOC Type": item["ioc_type"],
            "IOC": item["ioc"],
            "Overall Verdict": item["overall_verdict"],
            "Checked At": item["checked_at"]
        }

        for provider, result in item["results"].items():
            row[f"{provider} Status"] = result.get("status")
            row[f"{provider} Verdict"] = result.get("verdict")

            if provider == "VirusTotal":
                row["VT Malicious"] = result.get("malicious")
                row["VT Suspicious"] = result.get("suspicious")
                row["VT Reputation"] = result.get("reputation")

            if provider == "HybridAnalysis":
                row["HA Matches"] = result.get("total_matches")

            if provider == "MalwareBazaar":
                row["MB File Name"] = result.get("file_name")
                row["MB Signature"] = result.get("signature")

            if provider == "URLhaus":
                row["URLhaus Matches"] = result.get("total_urls")

        rows.append(row)

    if rows:
        with open(
            csv_path,
            "w",
            newline="",
            encoding="utf-8-sig"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=rows[0].keys()
            )
            writer.writeheader()
            writer.writerows(rows)

    return json_path, csv_path


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print(" FIN-WS-047 LAB | HASH & DOMAIN IOC CHECKER")
    print("=" * 60)

    print("\nAvailable providers:")
    print(f"  VirusTotal      : {'YES' if VT_API_KEY else 'NO'}")
    print(f"  Hybrid Analysis : {'YES' if HA_API_KEY else 'NO'}")
    print(f"  MalwareBazaar   : {'YES' if MB_AUTH_KEY else 'NO'}")
    print(f"  URLhaus         : {'YES' if URLHAUS_AUTH_KEY else 'NO'}")

    print("\nInput format:")
    print("  SHA256 / SHA1 / MD5")
    print("  Domain")
    print("\nMultiple IOC can be separated by comma or space.")
    print("Type 'exit' to quit.\n")

    while True:
        raw = input("IOC HASH/DOMAIN > ").strip()

        if raw.lower() in ("exit", "quit", "q"):
            print("Exiting...")
            break

        if not raw:
            continue

        candidates = re.split(r"[\s,;]+", raw)

        output = []
        seen = set()

        for candidate in candidates:
            if not candidate:
                continue

            hash_item = validate_hash(candidate)

            if hash_item:
                key = ("hash", hash_item["hash"])

                if key not in seen:
                    seen.add(key)
                    output.append(("hash", hash_item))

                continue

            domain = normalize_domain(candidate)

            if domain:
                key = ("domain", domain)

                if key not in seen:
                    seen.add(key)
                    output.append(("domain", domain))
            else:
                print(f"[!] Invalid IOC skipped: {candidate}")

        if not output:
            print("[!] No valid hash or domain found.")
            continue

        all_results = []

        for ioc_type, value in output:
            if ioc_type == "hash":
                all_results.append(check_hash(value))
            else:
                all_results.append(check_domain(value))

        json_path, csv_path = save_results(all_results)

        print("\n" + "=" * 60)
        print("SCAN COMPLETED")
        print("=" * 60)
        print(f"Total IOC checked : {len(all_results)}")
        print(f"JSON output       : {json_path}")
        print(f"CSV output        : {csv_path}")
        print("=" * 60)


if __name__ == "__main__":
    main()
