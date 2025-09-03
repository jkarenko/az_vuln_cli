#!/usr/bin/env python3
"""
Script to generate a concise remediation summary CSV
"""

import csv
import sys
from collections import defaultdict

def generate_summary(input_csv, output_csv):
    """Generate a concise summary CSV for Google Sheets tracking"""
    
    try:
        with open(input_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            data = list(reader)
    except FileNotFoundError:
        print(f"Error: CSV file '{input_csv}' not found.")
        return
    
    # Group by package and collect vulnerabilities
    package_groups = defaultdict(list)
    
    for row in data:
        package_key = f"{row['Package_Name']}@{row['Current_Version']}"
        package_groups[package_key].append(row)
    
    # Generate summary data
    summary_data = []
    
    for package_key, vulns in package_groups.items():
        package_name = vulns[0]['Package_Name']
        current_version = vulns[0]['Current_Version']
        
        # Get highest severity and CVSS score
        severities = [v['Severity'] for v in vulns]
        severity_priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
        highest_severity = min(severities, key=lambda x: severity_priority.get(x, 4))
        
        cvss_scores = [float(v['CVSS_Score']) for v in vulns if v['CVSS_Score'].replace('.', '').isdigit()]
        max_cvss = max(cvss_scores) if cvss_scores else 0
        
        # Get fixed versions (remove "Check Manually" entries)
        fixed_versions = set()
        for v in vulns:
            if v['Fixed_Version'] != 'Check Manually' and v['Fixed_Version'].strip():
                fixed_versions.add(v['Fixed_Version'])
        
        fixed_version_str = ', '.join(sorted(fixed_versions)) if fixed_versions else 'Check Manually'
        
        # Count vulnerabilities by severity
        vuln_counts = defaultdict(int)
        for v in vulns:
            vuln_counts[v['Severity']] += 1
        
        vuln_summary = ', '.join([f"{sev}: {count}" for sev, count in sorted(vuln_counts.items())])
        
        summary_data.append({
            'Image': vulns[0]['Image'],
            'Package_Name': package_name,
            'Current_Version': current_version,
            'Highest_Severity': highest_severity,
            'Max_CVSS_Score': f"{max_cvss:.1f}" if max_cvss > 0 else 'Unknown',
            'Vulnerability_Count': len(vulns),
            'Severity_Breakdown': vuln_summary,
            'Fixed_Version': fixed_version_str,
            'Priority': 'High' if highest_severity in ['Critical', 'High'] else 'Medium' if highest_severity == 'Medium' else 'Low',
            'Status': 'Not Started',
            'Assigned_To': '',
            'Target_Date': '',
            'Completed_Date': '',
            'Notes': ''
        })
    
    # Sort by priority and severity
    priority_order = {'High': 0, 'Medium': 1, 'Low': 2}
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    
    summary_data.sort(key=lambda x: (
        priority_order.get(x['Priority'], 3),
        severity_order.get(x['Highest_Severity'], 4),
        -float(x['Max_CVSS_Score']) if x['Max_CVSS_Score'] != 'Unknown' else 0
    ))
    
    # Write summary CSV
    fieldnames = [
        'Image', 'Package_Name', 'Current_Version', 'Highest_Severity', 'Max_CVSS_Score',
        'Vulnerability_Count', 'Severity_Breakdown', 'Fixed_Version', 'Priority',
        'Status', 'Assigned_To', 'Target_Date', 'Completed_Date', 'Notes'
    ]
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_data)
    
    print(f"✅ Generated concise summary CSV: {output_csv}")
    print(f"📊 Summarized {len(data)} vulnerabilities into {len(summary_data)} package entries")
    
    # Print statistics
    priority_stats = defaultdict(int)
    for row in summary_data:
        priority_stats[row['Priority']] += 1
    
    print(f"\n📈 Priority Breakdown:")
    for priority in ['High', 'Medium', 'Low']:
        if priority in priority_stats:
            print(f"  {priority}: {priority_stats[priority]} packages")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_summary.py <input_csv> <output_csv>")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    output_csv = sys.argv[2]
    
    generate_summary(input_csv, output_csv)
