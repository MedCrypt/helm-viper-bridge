#!/usr/bin/env python3
"""
Helm <-> Viper Vulnerability Sync Module

Transforms vulnerabilities from Helm format to Viper format and syncs them via bulk API.
"""

import requests
from typing import Dict, List, Optional
from datetime import datetime
from ssl_helper import get_ca_bundle

# API Configuration
VIPER_API_URL = "https://viper-xi.vercel.app/api"
SSL_VERIFY = get_ca_bundle()


def generate_cpe_from_helm_vuln(vuln: dict) -> List[str]:
    """
    Generate CPE 2.3 strings from Helm vulnerability data.

    Args:
        vuln: Vulnerability from Helm API

    Returns:
        List of CPE strings
    """
    cpes = []

    vendor = vuln.get("vendor_display_name", "").lower().replace(" ", "_").replace("-", "_")
    product = vuln.get("product_display_name", "").lower().replace(" ", "_").replace("-", "_")
    version = vuln.get("product_version_string", "*")

    # Clean up vendor and product names
    vendor = "".join(c for c in vendor if c.isalnum() or c == "_") or "unknown"
    product = "".join(c for c in product if c.isalnum() or c == "_") or "unknown"

    if vendor and product:
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        cpes.append(cpe)

    return cpes if cpes else ["cpe:2.3:a:unknown:unknown:*:*:*:*:*:*:*:*"]


def extract_description(vuln: dict) -> str:
    """Extract English description from vulnerability."""
    descriptions = vuln.get("description", [])
    if descriptions:
        # Find English description
        for desc in descriptions:
            if desc.get("lang_code") == "en":
                return desc.get("value", "")
        # Fallback to first description
        return descriptions[0].get("value", "")

    return vuln.get("vulnerability_summary", "No description available")


def generate_tags(vuln: dict) -> List[str]:
    """Generate tags for SARIF from vulnerability data."""
    tags = []

    if vuln.get("cisa_kev"):
        tags.append("cisa-kev")
    if vuln.get("exploit_db"):
        tags.append("exploit-db")
    if vuln.get("metasploit"):
        tags.append("metasploit")
    if vuln.get("top_cwe"):
        tags.append("top-cwe")
    if vuln.get("ai"):
        tags.append("ai-generated")

    patch_state = vuln.get("patch_state", "").lower()
    if patch_state:
        tags.append(f"patch-{patch_state}")

    return tags


def cvss_score_to_sarif_level(vuln: dict) -> str:
    """Convert CVSS score to SARIF level."""
    severities = vuln.get("vulnerability_severity", [])
    score = severities[0].get("score", 0.0) if severities else 0.0

    if score >= 9.0:
        return "error"
    elif score >= 7.0:
        return "error"
    elif score >= 4.0:
        return "warning"
    else:
        return "note"


def generate_sarif_from_helm_vuln(vuln: dict) -> dict:
    """
    Generate minimal SARIF format from Helm vulnerability.

    Args:
        vuln: Vulnerability from Helm API

    Returns:
        SARIF object
    """
    cve_id = vuln.get("vulnerability_key", "UNKNOWN")
    severities = vuln.get("vulnerability_severity", [])
    score = severities[0].get("score", 0.0) if severities else 0.0

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Helm",
                        "informationUri": "https://helm.medcrypt.co",
                        "version": "1.0.0",
                        "rules": [
                            {
                                "id": cve_id,
                                "shortDescription": {
                                    "text": vuln.get("vulnerability_summary", "")
                                },
                                "fullDescription": {
                                    "text": extract_description(vuln)
                                },
                                "help": {
                                    "text": extract_description(vuln),
                                    "markdown": extract_description(vuln)
                                },
                                "properties": {
                                    "security-severity": str(score),
                                    "tags": generate_tags(vuln)
                                }
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": cve_id,
                        "level": cvss_score_to_sarif_level(vuln),
                        "message": {
                            "text": vuln.get("vulnerability_summary", "")
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f"{vuln.get('product_display_name', 'unknown')}/{vuln.get('product_version_string', 'unknown')}"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }


def cvss_to_viper_severity(score: float) -> str:
    """
    Map CVSS score to Viper severity enum.

    Args:
        score: CVSS score (0-10)

    Returns:
        Severity string: "Critical", "High", "Medium", or "Low"
    """
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"


def extract_affected_components(vuln: dict) -> List[str]:
    """Extract component names from vulnerability."""
    components = []

    # Add product as component
    product = vuln.get("product_display_name")
    if product:
        components.append(product)

    # Add organization product if different
    org_product = vuln.get("organization_product_name")
    if org_product and org_product != product:
        components.append(org_product)

    return components if components else ["unknown"]


def extract_exploit_uri(vuln: dict) -> Optional[str]:
    """Extract exploit URI from vulnerability references."""
    if vuln.get("exploit_db"):
        # Try to find Exploit-DB link in references
        for ref in vuln.get("reference_link", []):
            href = ref.get("reference_link_href", "")
            if "exploit-db.com" in href or "exploitdb" in href:
                return href

    if vuln.get("metasploit"):
        # Try to find Metasploit link
        for ref in vuln.get("reference_link", []):
            href = ref.get("reference_link_href", "")
            if "metasploit" in href or "rapid7" in href:
                return href

    return None


def extract_upstream_api(vuln: dict) -> Optional[str]:
    """Extract upstream API link (prefer NVD)."""
    for ref in vuln.get("reference_link", []):
        href = ref.get("reference_link_href", "")
        source = ref.get("reference_link_source", "").lower()

        # Prefer NVD links
        if "nvd.nist.gov" in href or "nvd" in source:
            return href

    # Fallback to first reference
    refs = vuln.get("reference_link", [])
    if refs:
        return refs[0].get("reference_link_href")

    return None


def transform_helm_vuln_to_viper(helm_vuln: dict, device_group_id: Optional[str] = None, device_group_cpe: Optional[str] = None) -> dict:
    """
    Transform Helm vulnerability to Viper format.

    Args:
        helm_vuln: Vulnerability from Helm API
        device_group_id: Optional device group ID (not used currently)
        device_group_cpe: Optional device group CPE to link vulnerability

    Returns:
        Vulnerability in Viper format
    """
    # Extract primary severity
    severities = helm_vuln.get("vulnerability_severity", [])
    primary_severity = severities[0] if severities else {}
    cvss_score = primary_severity.get("score", 0.0)

    # Extract descriptions
    descriptions = helm_vuln.get("description", [])
    description = next(
        (d.get("value") for d in descriptions if d.get("lang_code") == "en"),
        helm_vuln.get("vulnerability_summary", "")
    )

    # Extract problems/impact
    problems = helm_vuln.get("problems", [])
    impact = next(
        (p.get("value") for p in problems if p.get("lang_code") == "en"),
        "No impact description available"
    )

    # Use device group CPE if provided, otherwise generate from vulnerability data
    cpes = [device_group_cpe] if device_group_cpe else generate_cpe_from_helm_vuln(helm_vuln)

    # Build vulnerability object, omitting null values
    vuln = {
        # REQUIRED
        "cpes": cpes,
        "sarif": generate_sarif_from_helm_vuln(helm_vuln),

        # OPTIONAL
        "cveId": helm_vuln.get("vulnerability_key"),
        "description": description,
        "narrative": helm_vuln.get("vulnerability_summary"),
        "impact": impact,
        "severity": cvss_to_viper_severity(cvss_score),
        "cvssScore": cvss_score,
        "affectedComponents": extract_affected_components(helm_vuln),
        "vendorId": helm_vuln.get("vulnerability_key", ""),
    }

    # Only include optional URL/ID fields when they have real values — Viper
    # rejects empty strings (expects valid URLs or omission of the field).
    exploit_uri = extract_exploit_uri(helm_vuln)
    if exploit_uri:
        vuln["exploitUri"] = exploit_uri

    upstream_api = extract_upstream_api(helm_vuln)
    if upstream_api:
        vuln["upstreamApi"] = upstream_api

    # deviceArtifactId requires at least 1 char; omit when not available
    # vuln["deviceArtifactId"] is intentionally omitted

    # Add CVSS vector if present
    cvss_vector = helm_vuln.get("cvss_v3_vector_string") or helm_vuln.get("cvss_v2_vector_string")
    if cvss_vector:
        vuln["cvssVector"] = cvss_vector

    return vuln


def sync_vulnerabilities_to_viper(
    viper_vulnerabilities: List[dict],
    viper_api_key: str
) -> Dict:
    """
    Bulk sync vulnerabilities to Viper API.

    Args:
        viper_vulnerabilities: List of vulnerabilities in Viper format
        viper_api_key: Viper API key

    Returns:
        Dict with sync results
    """
    try:
        url = f"{VIPER_API_URL}/v1/vulnerabilities/bulk"

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {viper_api_key}'
        }

        payload = {
            "vulnerabilities": viper_vulnerabilities
        }

        response = requests.post(url, json=payload, headers=headers, verify=SSL_VERIFY)

        if response.status_code == 200:
            created_vulns = response.json()
            return {
                'success': True,
                'synced_count': len(created_vulns),
                'failed_count': 0,
                'viper_vulnerabilities': created_vulns,
                'errors': []
            }
        else:
            return {
                'success': False,
                'synced_count': 0,
                'failed_count': len(viper_vulnerabilities),
                'viper_vulnerabilities': [],
                'errors': [f'HTTP {response.status_code}: {response.text}']
            }

    except Exception as e:
        return {
            'success': False,
            'synced_count': 0,
            'failed_count': len(viper_vulnerabilities),
            'viper_vulnerabilities': [],
            'errors': [str(e)]
        }


if __name__ == '__main__':
    # Test transformation with example data
    example_helm_vuln = {
        "vulnerability_key": "CVE-2024-1234",
        "vulnerability_summary": "Example vulnerability",
        "vendor_display_name": "OpenSSL Project",
        "product_display_name": "OpenSSL",
        "product_version_string": "1.1.1",
        "organization_product_name": "My Product",
        "vulnerability_severity": [{"score": 9.8}],
        "cvss_v3_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": [{"lang_code": "en", "value": "Detailed description here"}],
        "problems": [{"lang_code": "en", "value": "Impact description here"}],
        "reference_link": [
            {"reference_link_href": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"}
        ],
        "cisa_kev": True,
        "patch_state": "PATCH_AVAILABLE"
    }

    print("Testing transformation...")
    viper_format = transform_helm_vuln_to_viper(example_helm_vuln)

    import json
    print("\nViper Format:")
    print(json.dumps(viper_format, indent=2))
