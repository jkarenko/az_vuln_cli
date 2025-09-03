#!/usr/bin/env python3
"""
Create detailed comparison showing exactly which vulnerabilities are fixed,
introduced, or unchanged when moving from production to latest images.
"""

import csv
import sys
import os

def load_csv_data(file_path):
    """Load CSV data into a list of dictionaries."""
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                data.append(row)
        return data
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return []

def create_package_key(row):
    """Create a unique key for a package vulnerability."""
    return f"{row.get('Package_Name', 'Unknown')}|{row.get('Current_Version', 'Unknown')}"

def parse_severity_breakdown(severity_breakdown):
    """Parse severity breakdown string to extract counts."""
    import re
    
    if not severity_breakdown or severity_breakdown in ['N/A', 'Unknown', '']:
        return {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Unknown': 0}
    
    # Parse patterns like "Critical: 1, High: 3, Medium: 5"
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Unknown': 0}
    
    # Find all "SeverityLevel: Number" patterns
    matches = re.findall(r'(\w+):\s*(\d+)', str(severity_breakdown))
    for severity, count in matches:
        if severity in counts:
            counts[severity] = int(count)
    
    return counts

def generate_detailed_comparison():
    """Generate detailed vulnerability comparison CSV."""
    
    prod_file = "reports/production/vulnerabilities_summary.csv"
    latest_file = "reports/latest/vulnerabilities_summary.csv"
    prod_tracking_file = "reports/production/vulnerabilities_tracking.csv"
    output_file = "reports/comparison/detailed_vulnerability_comparison.csv"
    
    # Load data
    prod_data = load_csv_data(prod_file)
    latest_data = load_csv_data(latest_file)
    prod_tracking_data = load_csv_data(prod_tracking_file)
    
    if not prod_data:
        print(f"No production data found in {prod_file}")
        return
    
    if not latest_data:
        print(f"No latest data found in {latest_file}")
        return
    
    print(f"Loaded {len(prod_data)} production vulnerabilities")
    print(f"Loaded {len(latest_data)} latest vulnerabilities")
    print(f"Loaded {len(prod_tracking_data)} production tracking entries")
    
    # Create package to images mapping and vulnerability IDs mapping
    package_to_images = {}
    package_to_vulns = {}
    for row in prod_tracking_data:
        package_key = f"{row.get('Package_Name', 'Unknown')}|{row.get('Current_Version', 'Unknown')}"
        image = row.get('Image', 'Unknown')
        vuln_id = row.get('Vulnerability_ID', 'Unknown')
        
        if package_key not in package_to_images:
            package_to_images[package_key] = set()
        if package_key not in package_to_vulns:
            package_to_vulns[package_key] = set()
            
        package_to_images[package_key].add(image)
        if vuln_id != 'Unknown':
            package_to_vulns[package_key].add(vuln_id)
    
    # Create dictionaries for quick lookup
    prod_packages = {}
    latest_packages = {}
    
    for row in prod_data:
        key = create_package_key(row)
        prod_packages[key] = row
    
    for row in latest_data:
        key = create_package_key(row)
        latest_packages[key] = row
    
    # Analyze changes
    fixed_packages = []
    new_vulnerabilities = []
    unchanged_packages = []
    
    # Find packages fixed in latest (in production but not in latest)
    for key, prod_row in prod_packages.items():
        if key not in latest_packages:
            # Get affected images and vulnerabilities for this package
            affected_images = package_to_images.get(key, set())
            affected_images_str = '; '.join(sorted(affected_images)) if affected_images else 'Unknown'
            
            fixed_vulns = package_to_vulns.get(key, set())
            fixed_vulns_str = '; '.join(sorted(fixed_vulns)) if fixed_vulns else 'Unknown'
            
            # Parse severity counts from production data
            prod_severities = parse_severity_breakdown(prod_row.get('Severity_Breakdown', ''))
            
            fixed_packages.append({
                'Status': 'FIXED',
                'Package': prod_row.get('Package_Name', 'Unknown'),
                'Current_Version': prod_row.get('Current_Version', 'Unknown'),
                'Affected_Images': affected_images_str,
                'Fixed_Vulnerabilities': fixed_vulns_str,
                'Vulnerability_Count_Prod': prod_row.get('Vulnerability_Count', '0'),
                'Vulnerability_Count_Latest': '0',
                'Priority_Prod': prod_row.get('Priority', 'Unknown'),
                'Priority_Latest': 'N/A',
                'High_Severity_Prod': str(prod_severities['High']),
                'High_Severity_Latest': '0',
                'Critical_Severity_Prod': str(prod_severities['Critical']),
                'Critical_Severity_Latest': '0',
                'Impact': f"Eliminates {prod_row.get('Vulnerability_Count', '0')} vulnerabilities"
            })
    
    # Find new vulnerabilities in latest (not in production but in latest)
    for key, latest_row in latest_packages.items():
        if key not in prod_packages:
            # Parse severity counts from latest data
            latest_severities = parse_severity_breakdown(latest_row.get('Severity_Breakdown', ''))
            
            new_vulnerabilities.append({
                'Status': 'NEW',
                'Package': latest_row.get('Package_Name', 'Unknown'),
                'Current_Version': latest_row.get('Current_Version', 'Unknown'),
                'Affected_Images': 'N/A (Latest only)',
                'Fixed_Vulnerabilities': 'N/A (New in latest)',
                'Vulnerability_Count_Prod': '0',
                'Vulnerability_Count_Latest': latest_row.get('Vulnerability_Count', '0'),
                'Priority_Prod': 'N/A',
                'Priority_Latest': latest_row.get('Priority', 'Unknown'),
                'High_Severity_Prod': '0',
                'High_Severity_Latest': str(latest_severities['High']),
                'Critical_Severity_Prod': '0',
                'Critical_Severity_Latest': str(latest_severities['Critical']),
                'Impact': f"Introduces {latest_row.get('Vulnerability_Count', '0')} new vulnerabilities"
            })
    
    # Find unchanged packages (in both production and latest)
    for key, prod_row in prod_packages.items():
        if key in latest_packages:
            latest_row = latest_packages[key]
            prod_count = int(prod_row.get('Vulnerability_Count', '0'))
            latest_count = int(latest_row.get('Vulnerability_Count', '0'))
            
            if prod_count != latest_count:
                status = 'IMPROVED' if latest_count < prod_count else 'WORSENED'
                impact = f"Change: {prod_count} → {latest_count} vulnerabilities"
            else:
                status = 'UNCHANGED'
                impact = f"No change: {prod_count} vulnerabilities"
            
            # Get affected images and vulnerabilities for this package
            affected_images = package_to_images.get(key, set())
            affected_images_str = '; '.join(sorted(affected_images)) if affected_images else 'Unknown'
            
            current_vulns = package_to_vulns.get(key, set())
            current_vulns_str = '; '.join(sorted(current_vulns)) if current_vulns else 'Unknown'
            
            # Parse severity counts from both production and latest data
            prod_severities = parse_severity_breakdown(prod_row.get('Severity_Breakdown', ''))
            latest_severities = parse_severity_breakdown(latest_row.get('Severity_Breakdown', ''))
            
            unchanged_packages.append({
                'Status': status,
                'Package': prod_row.get('Package_Name', 'Unknown'),
                'Current_Version': prod_row.get('Current_Version', 'Unknown'),
                'Affected_Images': affected_images_str,
                'Fixed_Vulnerabilities': current_vulns_str if status in ['IMPROVED', 'WORSENED'] else 'Still present',
                'Vulnerability_Count_Prod': prod_row.get('Vulnerability_Count', '0'),
                'Vulnerability_Count_Latest': latest_row.get('Vulnerability_Count', '0'),
                'Priority_Prod': prod_row.get('Priority', 'Unknown'),
                'Priority_Latest': latest_row.get('Priority', 'Unknown'),
                'High_Severity_Prod': str(prod_severities['High']),
                'High_Severity_Latest': str(latest_severities['High']),
                'Critical_Severity_Prod': str(prod_severities['Critical']),
                'Critical_Severity_Latest': str(latest_severities['Critical']),
                'Impact': impact
            })
    
    # Combine all results
    all_results = fixed_packages + new_vulnerabilities + unchanged_packages
    
    # Sort by status priority (FIXED first, then NEW, then others)
    status_priority = {'FIXED': 0, 'IMPROVED': 1, 'NEW': 2, 'WORSENED': 3, 'UNCHANGED': 4}
    all_results.sort(key=lambda x: (
        status_priority.get(x['Status'], 5),
        -int(x.get('Vulnerability_Count_Prod', '0')),  # Higher vulnerability count first
        x.get('Package', '')
    ))
    
    # Write CSV
    if all_results:
        fieldnames = [
            'Status', 'Package', 'Current_Version', 'Affected_Images', 'Fixed_Vulnerabilities',
            'Vulnerability_Count_Prod', 'Vulnerability_Count_Latest',
            'Priority_Prod', 'Priority_Latest',
            'High_Severity_Prod', 'High_Severity_Latest',
            'Critical_Severity_Prod', 'Critical_Severity_Latest',
            'Impact'
        ]
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_results)
        
        print(f"\n✅ Detailed comparison created: {output_file}")
        print(f"📊 Summary:")
        print(f"   🎯 Packages FIXED: {len(fixed_packages)}")
        print(f"   ⚠️  NEW vulnerabilities: {len(new_vulnerabilities)}")
        print(f"   📈 IMPROVED packages: {len([p for p in unchanged_packages if p['Status'] == 'IMPROVED'])}")
        print(f"   📉 WORSENED packages: {len([p for p in unchanged_packages if p['Status'] == 'WORSENED'])}")
        print(f"   ➡️  UNCHANGED packages: {len([p for p in unchanged_packages if p['Status'] == 'UNCHANGED'])}")
        
        # Show top fixed packages
        if fixed_packages:
            print(f"\n🎯 Top packages that will be FIXED:")
            for i, pkg in enumerate(fixed_packages[:10]):
                vuln_count = pkg['Vulnerability_Count_Prod']
                print(f"   {i+1:2}. {pkg['Package']} ({vuln_count} vulnerabilities)")
        
        if new_vulnerabilities:
            print(f"\n⚠️  New vulnerabilities introduced:")
            for i, pkg in enumerate(new_vulnerabilities[:5]):
                vuln_count = pkg['Vulnerability_Count_Latest']
                print(f"   {i+1}. {pkg['Package']} ({vuln_count} vulnerabilities)")
    
    else:
        print("No data to write")

if __name__ == "__main__":
    generate_detailed_comparison()
