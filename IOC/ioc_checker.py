#!/usr/bin/env python3
"""
IOC ENRICHMENT TOOL
Providers: VirusTotal, AbuseIPDB, Hybrid Analysis, IPinfo, URLhaus, Filescan.io

Install:
    pip install requests python-dotenv

Run:
    python3 ioc_checker.py

API keys are read from .env in the same working directory.
MalwareBazaar has intentionally been removed.
"""

import csv
import ipaddress
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse
from zoneinfo import ZoneInfo

import requests
from dotenv import load_dotenv


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
IPINFO_API_TOKEN = os.getenv("IPINFO_API_TOKEN", "").strip()
IPINFO_API_MODE = os.getenv("IPINFO_API_MODE", "lite").strip().lower()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
FILESCAN_API_KEY = os.getenv("FILESCAN_API_KEY", "").strip()
FILESCAN_API_BASE_URL = os.getenv(
    "FILESCAN_API_BASE_URL", "https://www.filescan.io"
).strip().rstrip("/")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
SHODAN_BASE = "https://api.shodan.io"

VT_BASE = "https://www.virustotal.com/api/v3"
HA_BASE = "https://hybrid-analysis.com/api/v2"
OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = int(os.getenv("IOC_HTTP_TIMEOUT", "30"))
USER_AGENT = "IOC-Enrichment-Tool/2.3"
LOCAL_TZ = ZoneInfo("Asia/Jakarta")

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


# ============================================================
# COMMON / TIME FUNCTIONS
# ============================================================

def current_time():
    return datetime.now(LOCAL_TZ).isoformat(timespec="milliseconds")


def provider_result(provider, status, message="", data=None):
    return {
        "provider": provider,
        "status": status,
        "message": str(message),
        "data": data,
    }


class ProviderHTTPError(Exception):
    def __init__(self, status_code, message, response_data=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


def request_json(method, url, **kwargs):
    """Return decoded JSON and preserve useful API error details."""
    kwargs.setdefault("timeout", TIMEOUT)
    response = session.request(method, url, **kwargs)

    try:
        payload = response.json()
    except ValueError:
        payload = {"raw_response": response.text[:3000]}

    if not response.ok:
        if isinstance(payload, dict):
            detail = (
                payload.get("message")
                or payload.get("error")
                or payload.get("detail")
                or payload.get("query_status")
                or payload.get("raw_response")
                or response.reason
            )
        else:
            detail = response.reason

        raise ProviderHTTPError(
            response.status_code,
            f"HTTP {response.status_code}: {detail}",
            payload,
        )

    return payload


def not_applicable(provider, reason):
    return provider_result(provider, "NOT_APPLICABLE", reason)


def missing_key(provider, key_name):
    return provider_result(
        provider, "SKIPPED", f"API key not configured ({key_name})"
    )


def detect_ioc_type(value):
    """Return IP, DOMAIN, URL, or HASH. Reject unknown input."""
    value = value.strip()
    if not value:
        return None

    # URL with explicit scheme.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        parsed = urlparse(value)
        if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
            return "URL"
        return None

    # IP address.
    try:
        ipaddress.ip_address(value)
        return "IP"
    except ValueError:
        pass

    # MD5 / SHA1 / SHA256.
    if re.fullmatch(r"(?i)[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", value):
        return "HASH"

    # Domain.
    domain = value.lower().rstrip(".")
    if (
        len(domain) <= 253
        and "." in domain
        and all(
            re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                label,
            )
            for label in domain.split(".")
        )
        and re.fullmatch(r"[a-z]{2,63}", domain.split(".")[-1])
    ):
        return "DOMAIN"

    return None


def get_hash_type(value):
    return {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(value), "UNKNOWN")


def classify_provider_exception(provider, exc):
    if isinstance(exc, ProviderHTTPError):
        return provider_result(
            provider,
            "ERROR",
            str(exc),
            {"http_status": exc.status_code, "response": exc.response_data},
        )
    if isinstance(exc, requests.RequestException):
        return provider_result(provider, "ERROR", f"Request error: {exc}")
    return provider_result(provider, "ERROR", f"{type(exc).__name__}: {exc}")


def execute_provider(provider_name, function):
    started_at = current_time()
    start_clock = time.perf_counter()
    print(f"  [>] {provider_name}: checking...")

    try:
        result = function()
        if not isinstance(result, dict):
            result = provider_result(
                provider_name, "ERROR", "Unexpected provider response"
            )
    except Exception as exc:
        result = classify_provider_exception(provider_name, exc)

    completed_at = current_time()
    duration = round(time.perf_counter() - start_clock, 3)

    result["provider"] = provider_name
    result["requested_at"] = started_at if result["status"] not in {
        "NOT_APPLICABLE", "NOT_SUPPORTED", "SKIPPED"
    } else None
    result["completed_at"] = completed_at
    result["duration_seconds"] = duration

    print(
        f"  [-] {provider_name}: {result['status']} | "
        f"{result['message']} | {duration}s"
    )
    return result


# ============================================================
# VIRUSTOTAL - IP / DOMAIN / HASH
# ============================================================

def check_virustotal(ioc, ioc_type):
    if ioc_type not in {"IP", "DOMAIN", "HASH"}:
        return not_applicable("VirusTotal", f"IOC type {ioc_type} is not queried")

    if not VIRUSTOTAL_API_KEY:
        return missing_key("VirusTotal", "VIRUSTOTAL_API_KEY")

    if ioc_type == "IP":
        endpoint = "ip_addresses"
    elif ioc_type == "DOMAIN":
        endpoint = "domains"
    else:
        endpoint = "files"

    result = request_json(
        "GET",
        f"{VT_BASE}/{endpoint}/{quote(ioc, safe='')}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
    )

    attributes = result.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    elif stats:
        verdict = "clean"
    else:
        verdict = "unknown"

    details = {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "first_submission_date": attributes.get("first_submission_date"),
        "sha256": attributes.get("sha256"),
        "sha1": attributes.get("sha1"),
        "md5": attributes.get("md5"),
        "file_name": attributes.get("meaningful_name"),
        "file_type": attributes.get("type_description"),
        "file_size": attributes.get("size"),
    }

    if verdict == "unknown":
        return provider_result("VirusTotal", "NO_HIT", "No analysis statistics returned", details)
    return provider_result("VirusTotal", "OK", verdict, details)


# ============================================================
# ABUSEIPDB - IP ONLY
# ============================================================

def check_abuseipdb(ioc, ioc_type):
    if ioc_type != "IP":
        return not_applicable("AbuseIPDB", f"Does not support {ioc_type}")

    if not ABUSEIPDB_API_KEY:
        return missing_key("AbuseIPDB", "ABUSEIPDB_API_KEY")

    result = request_json(
        "GET",
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""},
    )

    data = result.get("data", {})
    score = data.get("abuseConfidenceScore")

    if score is None:
        return provider_result("AbuseIPDB", "ERROR", "abuseConfidenceScore missing", data)

    if score >= 75:
        verdict = "malicious"
    elif score > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    details = {
        "verdict": verdict,
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports"),
        "num_distinct_users": data.get("numDistinctUsers"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "is_tor": data.get("isTor"),
        "last_reported_at": data.get("lastReportedAt"),
    }
    return provider_result("AbuseIPDB", "OK", verdict, details)


# ============================================================
# HYBRID ANALYSIS - IP / DOMAIN / HASH
# ============================================================

def check_hybrid_analysis(ioc, ioc_type):
    """
    Hybrid Analysis hash lookup.

    The API has been documented with both GET query-string and POST
    form-encoded examples. Try POST first (the API's common search_hash
    implementation), then GET only when POST returns an empty result.
    """
    if ioc_type not in {"IP", "DOMAIN", "HASH"}:
        return not_applicable("HybridAnalysis", f"IOC type {ioc_type} is not queried")

    if not HYBRID_ANALYSIS_API_KEY:
        return missing_key("HybridAnalysis", "HYBRID_ANALYSIS_API_KEY")

    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    def extract_records(payload):
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            return []

        # Hybrid Analysis search responses commonly use {"count": n,
        # "result": [...]}. Keep compatibility with alternate wrappers.
        for key in ("result", "data", "reports", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = extract_records(value)
                if nested:
                    return nested

        # Some API responses return a single report object directly.
        report_markers = {
            "sha256", "sha1", "md5", "verdict", "threat_score",
            "submit_name", "job_id", "av_detect", "vx_family"
        }
        if report_markers.intersection(payload.keys()):
            return [payload]
        return []

    if ioc_type == "HASH":
        # POST form-encoded is supported by the Hybrid Analysis search_hash
        # endpoint and avoids relying on a GET-only implementation.
        response_payload = request_json(
            "POST",
            f"{HA_BASE}/search/hash",
            headers=headers,
            data={"hash": ioc},
        )
        records = extract_records(response_payload)
        lookup_method = "POST form (hash)"

        # Fallback for API deployments that expose GET query lookup.
        if not records:
            response_payload = request_json(
                "GET",
                f"{HA_BASE}/search/hash",
                headers=headers,
                params={"hash": ioc},
            )
            records = extract_records(response_payload)
            lookup_method = "GET query (hash)"
    elif ioc_type == "DOMAIN":
        response_payload = request_json(
            "POST",
            f"{HA_BASE}/search/terms",
            headers=headers,
            data={"domain": ioc},
        )
        records = extract_records(response_payload)
        lookup_method = "POST search terms (domain)"
    else:
        response_payload = request_json(
            "POST",
            f"{HA_BASE}/search/terms",
            headers=headers,
            data={"host": ioc},
        )
        records = extract_records(response_payload)
        lookup_method = "POST search terms (host)"

    if not records:
        response_preview = (
            response_payload if isinstance(response_payload, (dict, list))
            else str(response_payload)
        )
        return provider_result(
            "HybridAnalysis",
            "NO_HIT",
            "No matching report returned by Hybrid Analysis",
            {
                "total_results": 0,
                "lookup_method": lookup_method,
                "api_response": response_preview,
            },
        )

    samples = []
    verdicts = []
    for item in records:
        if not isinstance(item, dict):
            continue

        raw_verdict = str(item.get("verdict") or "").strip().lower()
        threat_score = item.get("threat_score")
        threat_level = item.get("threat_level")
        av_detect = item.get("av_detect")
        vx_family = item.get("vx_family") or item.get("family")

        # Preserve all fields useful for SOC triage, including family and
        # AV detections shown in the Hybrid Analysis report.
        samples.append({
            "sha256": item.get("sha256"),
            "sha1": item.get("sha1"),
            "md5": item.get("md5"),
            "verdict": item.get("verdict"),
            "threat_score": threat_score,
            "threat_level": threat_level,
            "av_detect": av_detect,
            "vx_family": vx_family,
            "submit_name": item.get("submit_name"),
            "filename": item.get("filename"),
            "analysis_start_time": item.get("analysis_start_time"),
            "job_id": item.get("job_id"),
            "state": item.get("state"),
            "classification_tags": item.get("classification_tags"),
            "tags": item.get("tags"),
            "submissions": item.get("submissions"),
        })

        # Threat score can establish a malicious/suspicious result even if
        # the API omits the textual verdict.
        try:
            score = float(threat_score) if threat_score is not None else None
        except (TypeError, ValueError):
            score = None

        if raw_verdict in {"malicious", "malware"} or (score is not None and score >= 70):
            verdicts.append("malicious")
        elif raw_verdict in {"suspicious"} or (score is not None and score >= 40):
            verdicts.append("suspicious")
        elif raw_verdict in {"clean", "benign"}:
            verdicts.append("clean")
        else:
            verdicts.append("review")

    if not samples:
        return provider_result(
            "HybridAnalysis",
            "NO_HIT",
            "API returned no usable report records",
            {
                "total_results": len(records),
                "lookup_method": lookup_method,
                "api_response": response_payload,
            },
        )

    if "malicious" in verdicts:
        verdict = "malicious"
    elif "suspicious" in verdicts:
        verdict = "suspicious"
    elif all(v == "clean" for v in verdicts):
        verdict = "clean"
    else:
        verdict = "review"

    return provider_result(
        "HybridAnalysis",
        "OK",
        verdict,
        {
            "verdict": verdict,
            "total_results": len(samples),
            "lookup_method": lookup_method,
            "results": samples,
        },
    )


# ============================================================
# IPINFO - IP ONLY
# ============================================================

def check_ipinfo(ioc, ioc_type):
    if ioc_type != "IP":
        return not_applicable("IPinfo", f"Does not support {ioc_type}")

    if not IPINFO_API_TOKEN:
        return missing_key("IPinfo", "IPINFO_API_TOKEN")

    if IPINFO_API_MODE == "lite":
        url = f"https://api.ipinfo.io/lite/{quote(ioc, safe='')}"
        result = request_json(
            "GET",
            url,
            headers={"Authorization": f"Bearer {IPINFO_API_TOKEN}"},
        )
    else:
        url = f"https://ipinfo.io/{quote(ioc, safe='')}/json"
        result = request_json(
            "GET",
            url,
            headers={"Authorization": f"Bearer {IPINFO_API_TOKEN}"},
        )

    details = {
        "ip": result.get("ip"),
        "hostname": result.get("hostname"),
        "asn": result.get("asn"),
        "as_name": result.get("as_name"),
        "as_domain": result.get("as_domain"),
        "country_code": result.get("country_code"),
        "country": result.get("country"),
        "continent_code": result.get("continent_code"),
        "continent": result.get("continent"),
        "city": result.get("city"),
        "region": result.get("region"),
        "org": result.get("org"),
        "loc": result.get("loc"),
    }

    if not details.get("ip") and not details.get("asn") and not details.get("country_code"):
        return provider_result("IPinfo", "ERROR", "Unexpected IPinfo response", result)

    return provider_result("IPinfo", "OK", "Enrichment available", details)


# ============================================================
# URLHAUS - IP / DOMAIN / URL / MD5 / SHA256
# ============================================================

def check_urlhaus(ioc, ioc_type):
    supported = {"IP", "DOMAIN", "URL", "HASH"}
    if ioc_type not in supported:
        return not_applicable("URLhaus", f"Does not support {ioc_type}")

    if ioc_type == "HASH" and get_hash_type(ioc) == "SHA1":
        return provider_result("URLhaus", "NOT_SUPPORTED", "URLhaus payload lookup supports MD5 and SHA256")

    if not URLHAUS_AUTH_KEY:
        return missing_key("URLhaus", "URLHAUS_AUTH_KEY")

    headers = {"Auth-Key": URLHAUS_AUTH_KEY}

    if ioc_type in {"IP", "DOMAIN"}:
        endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        payload = {"host": ioc}
    elif ioc_type == "URL":
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        payload = {"url": ioc}
    else:
        endpoint = "https://urlhaus-api.abuse.ch/v1/payload/"
        payload = {"md5_hash" if get_hash_type(ioc) == "MD5" else "sha256_hash": ioc}

    result = request_json("POST", endpoint, headers=headers, data=payload)
    query_status = result.get("query_status", "")

    if query_status == "no_results":
        return provider_result("URLhaus", "NO_HIT", "IOC not found", {"query_status": query_status})

    if query_status != "ok":
        return provider_result(
            "URLhaus", "ERROR", f"Unexpected query_status: {query_status or 'missing'}", result
        )

    if ioc_type in {"IP", "DOMAIN"}:
        entries = result.get("urls", []) or []
        count = len(entries)
        details = {"query_status": query_status, "url_count": count, "urls": entries[:10]}
    elif ioc_type == "URL":
        details = {
            "query_status": query_status,
            "url": result.get("url"),
            "url_status": result.get("url_status"),
            "threat": result.get("threat"),
            "tags": result.get("tags"),
            "date_added": result.get("date_added"),
        }
    else:
        details = {
            "query_status": query_status,
            "md5_hash": result.get("md5_hash"),
            "sha256_hash": result.get("sha256_hash"),
            "file_type": result.get("file_type"),
            "signature": result.get("signature"),
            "firstseen": result.get("firstseen"),
            "url_count": len(result.get("urls", []) or []),
        }

    return provider_result("URLhaus", "OK", "malicious", details)


# ============================================================
# FILESCAN.IO
# Preserve the reputation endpoints from the user's original script.
# ============================================================

def _filescan_find_verdict(payload):
    """
    Extract Filescan verdict fields from both reputation and nested report
    response shapes. Return (raw_verdict, source_object).
    """
    verdict_keys = (
        "overall_verdict",
        "final_verdict",
        "verdict",
    )

    def walk(obj):
        if isinstance(obj, dict):
            for key in verdict_keys:
                value = obj.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip(), obj
            # Common nested response containers.
            for key in (
                "result", "data", "reputation", "file", "report",
                "sourceArchive", "finalVerdict",
            ):
                if key in obj:
                    found = walk(obj[key])
                    if found:
                        return found
            # Search remaining nested objects/lists as a fallback.
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    found = walk(value)
                    if found:
                        return found
        elif isinstance(obj, list):
            for item in obj:
                found = walk(item)
                if found:
                    return found
        return None

    return walk(payload) or ("unknown", {})


def check_filescan(ioc, ioc_type):
    """
    Filescan reputation lookup:
      - SHA256: GET /api/reputation/hash?sha256=<hash>
      - IP/domain/URL: GET /api/reputation/{type}?ioc_value=<value>

    Uses the FILESCAN_API_KEY already configured in .env.
    """
    if ioc_type not in {"IP", "DOMAIN", "URL", "HASH"}:
        return not_applicable("Filescan.io", f"Does not support {ioc_type}")

    if not FILESCAN_API_KEY:
        return missing_key("Filescan.io", "FILESCAN_API_KEY")

    headers = {
        "X-Api-Key": FILESCAN_API_KEY,
        "Accept": "application/json",
    }

    if ioc_type == "HASH":
        hash_type = get_hash_type(ioc)
        if hash_type != "SHA256":
            return provider_result(
                "Filescan.io",
                "NOT_SUPPORTED",
                f"{hash_type} reputation lookup is not supported by this endpoint; SHA256 required",
                {"hash_type": hash_type},
            )

        endpoint = f"{FILESCAN_API_BASE_URL}/api/reputation/hash"
        params = {"sha256": ioc}
    else:
        endpoint = f"{FILESCAN_API_BASE_URL}/api/reputation/{ioc_type.lower()}"
        params = {"ioc_value": ioc}

    response_payload = request_json(
        "GET",
        endpoint,
        headers=headers,
        params=params,
    )

    if not isinstance(response_payload, (dict, list)):
        return provider_result(
            "Filescan.io",
            "ERROR",
            "Unexpected response format from Filescan.io",
            {"raw_response": str(response_payload)[:3000]},
        )

    raw_verdict, verdict_object = _filescan_find_verdict(response_payload)
    normalized_raw = raw_verdict.strip().lower().replace("-", "_").replace(" ", "_")

    verdict_map = {
        "malicious": "malicious",
        "likely_malicious": "malicious",
        "suspicious": "suspicious",
        "benign": "clean",
        "clean": "clean",
        "informational": "no_hit",
        "unknown": "unknown",
        "no_hit": "no_hit",
    }
    normalized_verdict = verdict_map.get(normalized_raw, "unknown")

    # Preserve useful reputation metadata when present.
    metadata = {}
    if isinstance(verdict_object, dict):
        for key in (
            "sha256", "hash", "ioc", "ioc_value",
            "overall_verdict", "verdict", "threat_level",
            "confidence", "scan_time", "first_seen", "last_seen",
            "mdcloud", "fuzzyhash", "community",
        ):
            if key in verdict_object:
                metadata[key] = verdict_object[key]

    metadata.update({
        "ioc": ioc,
        "ioc_type": ioc_type,
        "raw_verdict": raw_verdict,
        "normalized_verdict": normalized_verdict,
        "response": response_payload,
    })

    if normalized_verdict == "unknown":
        return provider_result(
            "Filescan.io",
            "NO_HIT",
            "API request succeeded but Filescan.io returned no recognized verdict",
            metadata,
        )

    return provider_result(
        "Filescan.io",
        "OK",
        normalized_verdict,
        metadata,
    )


# ============================================================
# SHODAN - IP ADDRESS ONLY
# ============================================================

def check_shodan(ioc, ioc_type):
    """
    Look up an IP address in Shodan's host information endpoint.
    Uses the REST endpoint /shodan/host/{ip}.
    """
    if ioc_type != "IP":
        return not_applicable("Shodan", f"Shodan host lookup supports IP only; received {ioc_type}")

    if not SHODAN_API_KEY:
        return missing_key("Shodan", "SHODAN_API_KEY")

    endpoint = f"{SHODAN_BASE}/shodan/host/{quote(ioc, safe='')}"
    result = request_json(
        "GET",
        endpoint,
        params={
            "key": SHODAN_API_KEY,
            "history": "false",
            "minify": "false",
        },
        headers={"Accept": "application/json"},
    )

    if not isinstance(result, dict):
        return provider_result(
            "Shodan", "ERROR", "Unexpected response format from Shodan",
            {"response": result},
        )

    banners = result.get("data") or []
    ports = result.get("ports") or []
    vulns = result.get("vulns") or []
    tags = result.get("tags") or []

    # An empty host record is still a successful lookup, but it has no
    # observed services/banners to enrich the IOC with.
    if not banners and not ports and not vulns and not result.get("hostnames"):
        return provider_result(
            "Shodan",
            "NO_HIT",
            "IP found by API but no host services or banners were returned",
            {
                "ip": result.get("ip_str", ioc),
                "last_update": result.get("last_update"),
                "org": result.get("org"),
                "isp": result.get("isp"),
                "asn": result.get("asn"),
                "country_name": (result.get("country_name") or
                                 (result.get("location") or {}).get("country_name")),
                "city": (result.get("city") or
                         (result.get("location") or {}).get("city")),
                "ports": ports,
                "hostnames": result.get("hostnames") or [],
                "domains": result.get("domains") or [],
                "tags": tags,
                "vulns": vulns,
                "banner_count": len(banners),
            },
        )

    location = result.get("location") or {}
    banner_details = []
    for banner in banners[:50]:
        if not isinstance(banner, dict):
            continue
        banner_details.append({
            "port": banner.get("port"),
            "transport": banner.get("transport"),
            "protocol": banner.get("_shodan", {}).get("module")
                if isinstance(banner.get("_shodan"), dict) else None,
            "product": banner.get("product"),
            "version": banner.get("version"),
            "module": banner.get("module"),
            "timestamp": banner.get("timestamp"),
            "hostnames": banner.get("hostnames") or [],
            "domains": banner.get("domains") or [],
            "http": banner.get("http"),
            "ssl": banner.get("ssl"),
            "data": (banner.get("data") or "")[:2000],
        })

    details = {
        "ip": result.get("ip_str", ioc),
        "ip_integer": result.get("ip"),
        "organization": result.get("org"),
        "isp": result.get("isp"),
        "asn": result.get("asn"),
        "operating_system": result.get("os"),
        "country": result.get("country_name") or location.get("country_name"),
        "country_code": location.get("country_code"),
        "city": result.get("city") or location.get("city"),
        "region_code": location.get("region_code"),
        "postal_code": location.get("postal_code"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "last_update": result.get("last_update"),
        "hostnames": result.get("hostnames") or [],
        "domains": result.get("domains") or [],
        "ports": ports,
        "tags": tags,
        "vulns": vulns,
        "vuln_count": len(vulns),
        "banner_count": len(banners),
        "banners": banner_details,
        "shodan_url": f"https://www.shodan.io/host/{ioc}",
    }

    # Shodan is an exposure/internet asset intelligence source. Open ports,
    # banners or CVEs alone are not automatically malware verdicts.
    return provider_result(
        "Shodan",
        "OK",
        f"Host information found | {len(ports)} port(s) | {len(banners)} banner(s) | {len(vulns)} vulnerability reference(s)",
        details,
    )


# ============================================================
# OVERALL VERDICT
# ============================================================

def calculate_verdict(results):
    # Ignore providers that did not actually query the IOC.
    queried = [
        r for r in results
        if r["status"] not in {"NOT_APPLICABLE", "NOT_SUPPORTED", "SKIPPED"}
    ]

    if not queried:
        return {
            "overall_verdict": "INCONCLUSIVE",
            "reason": "No applicable provider was queried",
            "queried_providers": 0,
            "error_providers": 0,
            "skipped_providers": len(results),
        }

    provider_verdicts = []
    errors = []
    for item in queried:
        if item["status"] == "ERROR":
            errors.append(item["provider"])
            continue

        data = item.get("data") or {}
        normalized = str(
            data.get("verdict")
            or data.get("normalized_verdict")
            or item.get("message", "")
        ).lower()

        if normalized == "malicious":
            provider_verdicts.append("MALICIOUS")
        elif normalized == "suspicious":
            provider_verdicts.append("SUSPICIOUS")
        elif normalized in {"clean", "no_hit", "unknown", "review", "enrichment available"}:
            continue

    if "MALICIOUS" in provider_verdicts:
        overall = "MALICIOUS"
        reason = "At least one queried provider returned a malicious verdict"
    elif "SUSPICIOUS" in provider_verdicts:
        overall = "SUSPICIOUS"
        reason = "At least one queried provider returned a suspicious verdict"
    elif errors:
        overall = "INCONCLUSIVE"
        reason = "One or more applicable providers returned an error: " + ", ".join(errors)
    elif any(r["status"] == "OK" for r in queried):
        overall = "NO_MALICIOUS_HIT"
        reason = "No malicious/suspicious verdict from providers that were queried"
    elif all(r["status"] == "NO_HIT" for r in queried):
        overall = "NO_MALICIOUS_HIT"
        reason = "No hit found by applicable providers"
    else:
        overall = "INCONCLUSIVE"
        reason = "Results are insufficient to determine a verdict"

    return {
        "overall_verdict": overall,
        "reason": reason,
        "queried_providers": len(queried),
        "error_providers": len(errors),
        "skipped_providers": sum(
            1 for r in results
            if r["status"] in {"SKIPPED", "NOT_APPLICABLE", "NOT_SUPPORTED"}
        ),
    }


# ============================================================
# SCAN IOC
# ============================================================

def scan_ioc(ioc):
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)

    if not ioc_type:
        print(f"[!] Invalid IOC: {ioc}")
        return None

    if ioc_type == "DOMAIN":
        ioc = ioc.lower().rstrip(".")

    print("\n" + "=" * 72)
    print(f"IOC       : {ioc}")
    print(f"IOC TYPE  : {ioc_type}")
    if ioc_type == "HASH":
        print(f"HASH TYPE : {get_hash_type(ioc)}")
    print(f"SCAN TIME : {current_time()}")
    print("=" * 72)

    providers = [
        ("AbuseIPDB", lambda: check_abuseipdb(ioc, ioc_type)),
        ("VirusTotal", lambda: check_virustotal(ioc, ioc_type)),
        ("HybridAnalysis", lambda: check_hybrid_analysis(ioc, ioc_type)),
        ("IPinfo", lambda: check_ipinfo(ioc, ioc_type)),
        ("URLhaus", lambda: check_urlhaus(ioc, ioc_type)),
        ("Filescan.io", lambda: check_filescan(ioc, ioc_type)),
        ("Shodan", lambda: check_shodan(ioc, ioc_type)),
    ]

    results = [
        execute_provider(provider_name, function)
        for provider_name, function in providers
    ]

    summary = calculate_verdict(results)
    print("\nOVERALL VERDICT:", summary["overall_verdict"])
    print("REASON         :", summary["reason"])

    return {
        "ioc_type": ioc_type,
        "hash_type": get_hash_type(ioc) if ioc_type == "HASH" else None,
        "ioc": ioc,
        "checked_at": current_time(),
        "timezone": "Asia/Jakarta",
        "overall_verdict": summary["overall_verdict"],
        "verdict_reason": summary["reason"],
        "provider_summary": summary,
        "results": results,
    }


# ============================================================
# SAVE JSON AND CSV
# ============================================================

def save_results(results):
    timestamp = datetime.now(LOCAL_TZ).strftime("%Y%m%d_%H%M%S")
    json_file = OUTPUT_DIR / f"ioc_enrichment_{timestamp}.json"
    csv_file = OUTPUT_DIR / f"ioc_enrichment_{timestamp}.csv"

    summary = {
        "total_ioc_checked": len(results),
        "malicious": sum(r["overall_verdict"] == "MALICIOUS" for r in results),
        "suspicious": sum(r["overall_verdict"] == "SUSPICIOUS" for r in results),
        "no_malicious_hit": sum(r["overall_verdict"] == "NO_MALICIOUS_HIT" for r in results),
        "inconclusive": sum(r["overall_verdict"] == "INCONCLUSIVE" for r in results),
    }

    output = {
        "generated_at": current_time(),
        "timezone": "Asia/Jakarta",
        "summary": summary,
        "results": results,
    }

    with json_file.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=4, ensure_ascii=False)

    fields = [
        "ioc", "ioc_type", "hash_type", "overall_verdict", "verdict_reason",
        "checked_at", "provider", "status", "message", "requested_at",
        "completed_at", "duration_seconds", "provider_data",
    ]

    with csv_file.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for item in results:
            for provider in item["results"]:
                writer.writerow({
                    "ioc": item["ioc"],
                    "ioc_type": item["ioc_type"],
                    "hash_type": item.get("hash_type"),
                    "overall_verdict": item["overall_verdict"],
                    "verdict_reason": item["verdict_reason"],
                    "checked_at": item["checked_at"],
                    "provider": provider.get("provider"),
                    "status": provider.get("status"),
                    "message": provider.get("message"),
                    "requested_at": provider.get("requested_at"),
                    "completed_at": provider.get("completed_at"),
                    "duration_seconds": provider.get("duration_seconds"),
                    "provider_data": json.dumps(provider.get("data"), ensure_ascii=False),
                })

    print("\n" + "=" * 72)
    print("SCAN COMPLETED")
    print("=" * 72)
    print(f"Total IOC checked : {summary['total_ioc_checked']}")
    print(f"Malicious         : {summary['malicious']}")
    print(f"Suspicious        : {summary['suspicious']}")
    print(f"No malicious hit  : {summary['no_malicious_hit']}")
    print(f"Inconclusive      : {summary['inconclusive']}")
    print(f"\nJSON output       : {json_file.resolve()}")
    print(f"CSV output        : {csv_file.resolve()}")
    print("=" * 72)


# ============================================================
# INPUT / MAIN
# ============================================================

def main():
    print("=" * 72)
    print("IOC ENRICHMENT TOOL")
    print("IP | DOMAIN | URL | HASH (MD5 / SHA1 / SHA256)")
    print("=" * 72)
    print("\nMasukkan IOC dipisahkan koma atau titik koma.")
    print("Contoh: 8.8.8.8, example.com, https://example.com/path, <SHA256>")
    print("Ketik 'exit' untuk keluar.\n")

    user_input = input("IOC > ").strip()
    if user_input.lower() in {"exit", "quit", "q"}:
        return
    if not user_input:
        print("[!] Input IOC kosong.")
        return

    # URLs may contain commas, so split only on semicolons/newlines when URL-like
    # input is present. For the common IP/domain/hash batch, comma/space works.
    if "://" in user_input:
        raw_iocs = [part.strip() for part in re.split(r"[;\n]+", user_input) if part.strip()]
    else:
        raw_iocs = re.split(r"[\s,;]+", user_input)

    unique_iocs = list(dict.fromkeys(item.strip() for item in raw_iocs if item.strip()))
    valid_iocs = []
    invalid_iocs = []

    for item in unique_iocs:
        if detect_ioc_type(item):
            valid_iocs.append(item)
        else:
            invalid_iocs.append(item)

    if invalid_iocs:
        print("\n[!] IOC tidak valid:")
        for item in invalid_iocs:
            print(f"  - {item}")

    if not valid_iocs:
        print("\n[!] Tidak ada IOC valid.")
        return

    print(f"\n[*] Total valid IOC: {len(valid_iocs)}")
    results = []

    for ioc in valid_iocs:
        try:
            result = scan_ioc(ioc)
            if result:
                results.append(result)
        except KeyboardInterrupt:
            print("\n[!] Scan dihentikan oleh user.")
            break
        except Exception as exc:
            print(f"[!] Unexpected error for {ioc}: {type(exc).__name__}: {exc}")

    if results:
        save_results(results)
    else:
        print("[!] Tidak ada hasil scan.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Program dihentikan.")
