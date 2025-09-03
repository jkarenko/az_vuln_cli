#!/usr/bin/env python3
"""
Script to generate Jira-formatted remediation tracking from CSV data
"""

import csv
import sys
from collections import defaultdict

def generate_jira_epic(csv_file, output_file):
    """Generate a Jira epic format from the CSV data"""
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            data = list(reader)
    except FileNotFoundError:
        print(f"Error: CSV file '{csv_file}' not found.")
        return
    
    # Group vulnerabilities by severity and package
    severity_groups = defaultdict(list)
    package_vulns = defaultdict(list)
    
    for row in data:
        severity = row["Severity"]
        package = row["Package_Name"]
        severity_groups[severity].append(row)
        package_vulns[package].append(row)
    
    # Generate Jira epic content
    content = []
    
    # Epic header
    content.append("h1. Security Remediation Epic - Container Image Vulnerabilities")
    content.append("")
    content.append(f"*Image:* {data[0]['Image'] if data else 'Unknown'}")
    content.append(f"*Total Vulnerabilities:* {len(data)}")
    content.append("")
    
    # Summary by severity
    content.append("h2. Summary by Severity")
    content.append("")
    severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
    
    for severity in severity_order:
        if severity in severity_groups:
            count = len(severity_groups[severity])
            content.append(f"* *{severity}:* {count} vulnerabilities")
    
    content.append("")
    
    # Critical and High severity stories
    content.append("h2. Priority Stories")
    content.append("")
    
    story_counter = 1
    for severity in ["Critical", "High"]:
        if severity in severity_groups:
            content.append(f"h3. {severity} Severity Vulnerabilities")
            content.append("")
            
            for vuln in severity_groups[severity]:
                content.append(f"h4. Story {story_counter}: Fix {vuln['Vulnerability_ID']} in {vuln['Package_Name']}")
                content.append("")
                content.append(f"*Vulnerability ID:* {vuln['Vulnerability_ID']}")
                content.append(f"*Package:* {vuln['Package_Name']} ({vuln['Current_Version']})")
                content.append(f"*Severity:* {vuln['Severity']} (CVSS: {vuln['CVSS_Score']})")
                content.append(f"*Fixed Version:* {vuln['Fixed_Version']}")
                content.append("")
                content.append("*Acceptance Criteria:*")
                content.append(f"- [ ] Update {vuln['Package_Name']} to fixed version")
                content.append("- [ ] Verify vulnerability is resolved")
                content.append("- [ ] Update container image")
                content.append("- [ ] Deploy and test")
                content.append("")
                content.append(f"*Description:*")
                content.append(f"{vuln['Description']}")
                content.append("")
                content.append("---")
                content.append("")
                story_counter += 1
    
    # Package-based grouping for Medium/Low priority
    content.append("h2. Medium/Low Priority - Grouped by Package")
    content.append("")
    
    medium_low_packages = set()
    for severity in ["Medium", "Low"]:
        for vuln in severity_groups.get(severity, []):
            medium_low_packages.add(vuln['Package_Name'])
    
    for package in sorted(medium_low_packages):
        vulns_for_package = [v for v in package_vulns[package] 
                           if v['Severity'] in ['Medium', 'Low']]
        if vulns_for_package:
            content.append(f"h4. Story {story_counter}: Remediate vulnerabilities in {package}")
            content.append("")
            content.append(f"*Package:* {package}")
            content.append(f"*Vulnerabilities:*")
            
            for vuln in vulns_for_package:
                content.append(f"- {vuln['Vulnerability_ID']} ({vuln['Severity']}, CVSS: {vuln['CVSS_Score']})")
            
            content.append("")
            content.append("*Acceptance Criteria:*")
            content.append(f"- [ ] Analyze all vulnerabilities in {package}")
            content.append(f"- [ ] Update {package} to latest secure version")
            content.append("- [ ] Verify all vulnerabilities are resolved")
            content.append("- [ ] Update container image")
            content.append("")
            content.append("---")
            content.append("")
            story_counter += 1
    
    # Write output
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(content))
    
    print(f"✅ Generated Jira epic format: {output_file}")
    print(f"📊 Created {story_counter - 1} user stories")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_jira_format.py <input_csv> <output_file>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    output_file = sys.argv[2]
    
    generate_jira_epic(csv_file, output_file)
