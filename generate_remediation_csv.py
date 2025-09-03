#!/usr/bin/env python3
"""
Script to parse Trivy SBOM output and generate a remediation tracking CSV
mapping image → vulnerable package → fixed version.
"""

import json
import csv
import sys
from typing import Dict, List, Set
import re

def extract_image_name(sbom_data: Dict) -> str:
    """Extract the container image name from SBOM metadata."""
    try:
        return sbom_data["metadata"]["component"]["name"]
    except KeyError:
        return "Unknown Image"

def get_package_info(components: List[Dict], bom_ref: str) -> Dict:
    """Find package information by bom-ref."""
    for component in components:
        if component.get("bom-ref") == bom_ref:
            return {
                "name": component.get("name", "Unknown"),
                "version": component.get("version", "Unknown"),
                "type": component.get("type", "Unknown"),
                "purl": component.get("purl", "")
            }
    return {"name": "Unknown", "version": "Unknown", "type": "Unknown", "purl": ""}

def extract_fixed_version(vulnerability: Dict) -> str:
    """Extract fixed version information from vulnerability data."""
    fixed_versions = set()
    
    # Check if there are any affects with version ranges that indicate fixes
    for affect in vulnerability.get("affects", []):
        for version_info in affect.get("versions", []):
            status = version_info.get("status", "")
            version = version_info.get("version", "")
            
            # Look for patterns that indicate fixed versions
            if "fixed" in status.lower():
                fixed_versions.add(version)
            elif "patched" in status.lower():
                fixed_versions.add(version)
    
    # Check advisories for version fix information
    for advisory in vulnerability.get("advisories", []):
        url = advisory.get("url", "")
        # Sometimes fix information is in the URL structure
        if "fixed" in url.lower():
            # Try to extract version from URL patterns
            version_match = re.search(r'(\d+\.[\d\.]+)', url)
            if version_match:
                fixed_versions.add(version_match.group(1))
    
    # Return the fixed versions found, or "Check Manually" if none found
    if fixed_versions:
        return ", ".join(sorted(fixed_versions))
    else:
        return "Check Manually"

def generate_remediation_csv(sbom_file: str, output_file: str):
    """Generate remediation tracking CSV from Trivy SBOM output."""
    
    try:
        with open(sbom_file, 'r') as f:
            sbom_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: SBOM file '{sbom_file}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in SBOM file: {e}")
        sys.exit(1)
    
    image_name = extract_image_name(sbom_data)
    components = sbom_data.get("components", [])
    vulnerabilities = sbom_data.get("vulnerabilities", [])
    
    # Prepare CSV data
    csv_data = []
    processed_vulns = set()  # To avoid duplicates
    
    print(f"Processing {len(vulnerabilities)} vulnerabilities...")
    
    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "Unknown")
        
        # Skip if we've already processed this vulnerability
        if vuln_id in processed_vulns:
            continue
        processed_vulns.add(vuln_id)
        
        severity = "Unknown"
        cvss_score = "Unknown"
        
        # Extract severity and CVSS score
        for rating in vuln.get("ratings", []):
            if rating.get("severity"):
                severity = rating["severity"].title()
            if rating.get("score"):
                cvss_score = str(rating["score"])
                break
        
        # Clean description by removing newlines and extra whitespace
        raw_description = vuln.get("description", "")
        # Replace newlines and multiple spaces with single space
        clean_description = re.sub(r'\s+', ' ', raw_description.strip())
        # Truncate if too long
        description = clean_description[:200] + "..." if len(clean_description) > 200 else clean_description
        
        # Process each affected package
        for affect in vuln.get("affects", []):
            package_ref = affect.get("ref", "")
            package_info = get_package_info(components, package_ref)
            
            # If we couldn't find the package in components, try to parse from ref
            if package_info["name"] == "Unknown" and package_ref:
                if "pkg:" in package_ref:
                    # Parse purl format: pkg:type/namespace/name@version
                    try:
                        parts = package_ref.split("/")
                        if len(parts) >= 2:
                            name_version = parts[-1].split("@")
                            package_info["name"] = name_version[0]
                            if len(name_version) > 1:
                                package_info["version"] = name_version[1].split("?")[0]  # Remove query params
                    except:
                        pass
            
            fixed_version = extract_fixed_version(vuln)
            
            csv_row = {
                "Image": image_name,
                "Vulnerability_ID": vuln_id,
                "Package_Name": package_info["name"],
                "Current_Version": package_info["version"],
                "Package_Type": package_info["type"],
                "Severity": severity,
                "CVSS_Score": cvss_score,
                "Fixed_Version": fixed_version,
                "Description": description,
                "Status": "Pending",
                "Notes": "",
                "Assigned_To": "",
                "Target_Date": "",
                "Completed_Date": ""
            }
            
            csv_data.append(csv_row)
    
    # Sort by severity (Critical, High, Medium, Low) and then by CVSS score
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    csv_data.sort(key=lambda x: (severity_order.get(x["Severity"], 4), -float(x["CVSS_Score"]) if x["CVSS_Score"].replace('.', '').isdigit() else 0))
    
    # Write CSV file
    if csv_data:
        fieldnames = [
            "Image", "Vulnerability_ID", "Package_Name", "Current_Version", 
            "Package_Type", "Severity", "CVSS_Score", "Fixed_Version",
            "Description", "Status", "Notes", "Assigned_To", "Target_Date", "Completed_Date"
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_data)
        
        print(f"✅ Generated remediation tracking CSV: {output_file}")
        print(f"📊 Found {len(csv_data)} vulnerability entries")
        
        # Print summary statistics
        severity_counts = {}
        for row in csv_data:
            severity = row["Severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"\n📈 Vulnerability Summary:")
        for severity in ["Critical", "High", "Medium", "Low", "Unknown"]:
            if severity in severity_counts:
                print(f"  {severity}: {severity_counts[severity]}")
                
    else:
        print("⚠️  No vulnerabilities found in the SBOM file.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_remediation_csv.py <sbom_file.json> <output_file.csv>")
        sys.exit(1)
    
    sbom_file = sys.argv[1]
    output_file = sys.argv[2]
    
    generate_remediation_csv(sbom_file, output_file)
