#!/usr/bin/env python3
"""
Update the Fixed_Version column in vulnerability tracking CSV by comparing
AKS images with their corresponding latest ACR versions to identify actual
fixes available in newer image versions.
"""

import csv
import json
import sys
import re
from pathlib import Path
from typing import Dict, Set, List, Tuple

def load_sbom_vulnerabilities(sbom_file: str) -> Dict[str, Set[str]]:
    """Load vulnerabilities from an SBOM file."""
    try:
        with open(sbom_file, 'r') as f:
            sbom_data = json.load(f)
        
        vulnerabilities = set()
        
        # Extract vulnerabilities from SBOM
        if 'vulnerabilities' in sbom_data:
            for vuln in sbom_data['vulnerabilities']:
                vuln_id = vuln.get('id', '')
                if vuln_id:
                    vulnerabilities.add(vuln_id)
        
        return vulnerabilities
        
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def normalize_image_name(image: str) -> str:
    """Normalize image name for comparison (remove tag/digest)."""
    # Remove tag or digest
    image = re.sub(r'[:|@].*$', '', image)
    return image

def find_acr_image_version(current_image: str, acr_sbom_dir: str) -> str:
    """Find the corresponding ACR version of an image in the ACR SBOM directory."""
    base_image = normalize_image_name(current_image)
    base_pattern = base_image.replace('/', '__').replace(':', '__')
    
    # Debug output removed
    
    # Look for any SBOM file that matches this base image (regardless of tag)
    acr_sbom_dir_path = Path(acr_sbom_dir)
    if not acr_sbom_dir_path.exists():
        return None
    
    # Find all SBOM files that match the base image pattern
    matching_files = []
    for sbom_file in acr_sbom_dir_path.glob('*.json'):
        if sbom_file.name.startswith(base_pattern + '__'):
            matching_files.append(sbom_file)
    
    if not matching_files:
        return None
    
    # Take the first match (assuming scan phase ensures we have the newest)
    # Convert filename back to image name
    chosen_file = matching_files[0]
    filename = chosen_file.stem  # remove .json
    
    # Convert back: registry__imagename__tag -> registry/imagename:tag
    parts = filename.split('__')
    
    if len(parts) >= 3:
        registry = parts[0]
        image_path = '/'.join(parts[1:-1])
        tag = parts[-1]
        return f"{registry}/{image_path}:{tag}"
    
    return None

def compare_image_vulnerabilities(current_sbom: str, latest_sbom: str) -> Tuple[Set[str], Set[str]]:
    """Compare vulnerabilities between current and latest image versions."""
    current_vulns = load_sbom_vulnerabilities(current_sbom)
    latest_vulns = load_sbom_vulnerabilities(latest_sbom)
    
    # Vulnerabilities fixed in latest (present in current, absent in latest)
    fixed_vulns = current_vulns - latest_vulns
    
    # New vulnerabilities in latest (absent in current, present in latest)
    new_vulns = latest_vulns - current_vulns
    
    return fixed_vulns, new_vulns

def update_fixed_versions(tracking_csv: str, current_sbom_dir: str, latest_sbom_dir: str, output_csv: str):
    """Update Fixed_Version column based on vulnerability comparison."""
    
    print(f"🔄 Analyzing vulnerabilities between {current_sbom_dir} and {latest_sbom_dir}")
    
    # Load the tracking CSV
    rows = []
    with open(tracking_csv, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    # Group vulnerabilities by image
    image_vulns = {}
    for row in rows:
        image = row['Image']
        vuln_id = row['Vulnerability_ID']
        
        if image not in image_vulns:
            image_vulns[image] = []
        image_vulns[image].append(row)
    
    print(f"📊 Processing {len(image_vulns)} unique images...")
    
    updated_count = 0
    processed_count = 0
    
    # Process each image
    for image, vulns in image_vulns.items():
        processed_count += 1
        
        # Find corresponding SBOM files
        current_sbom_name = image.replace('/', '__').replace(':', '__') + '.json'
        current_sbom_path = Path(current_sbom_dir) / current_sbom_name
        
        if not current_sbom_path.exists():
            continue
        
        # Find corresponding ACR version
        acr_image = find_acr_image_version(image, latest_sbom_dir)
        if not acr_image:
            continue
            
        acr_sbom_name = acr_image.replace('/', '__').replace(':', '__') + '.json'
        acr_sbom_path = Path(latest_sbom_dir) / acr_sbom_name
        
        if not acr_sbom_path.exists():
            continue
        
        # Compare vulnerabilities
        fixed_vulns, new_vulns = compare_image_vulnerabilities(str(current_sbom_path), str(acr_sbom_path))
        
        if fixed_vulns:
            # Update rows for this image where vulnerabilities are fixed
            for row in vulns:
                vuln_id = row['Vulnerability_ID']
                if vuln_id in fixed_vulns and row['Fixed_Version'] == 'Check Manually':
                    row['Fixed_Version'] = acr_image
                    updated_count += 1
        
        if processed_count % 10 == 0:
            print(f"  📈 Processed {processed_count}/{len(image_vulns)} images, updated {updated_count} vulnerabilities")
    
    # Write updated CSV
    if updated_count > 0:
        with open(output_csv, 'w', newline='') as f:
            fieldnames = rows[0].keys()
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"✅ Updated {updated_count} vulnerabilities with specific fixed versions")
        print(f"📁 Updated file saved to: {output_csv}")
    else:
        print("ℹ️  No vulnerabilities could be updated with specific fixed versions")

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 update_fixed_versions.py <tracking_csv> <current_sbom_dir> <latest_sbom_dir> <output_csv>")
        print("Example: python3 update_fixed_versions.py reports/prod/vulnerabilities_tracking.csv sbom_reports/production sbom_reports/latest reports/prod/vulnerabilities_tracking_updated.csv")
        sys.exit(1)
    
    tracking_csv = sys.argv[1]
    current_sbom_dir = sys.argv[2]
    latest_sbom_dir = sys.argv[3]
    output_csv = sys.argv[4]
    
    if not Path(tracking_csv).exists():
        print(f"❌ Tracking CSV not found: {tracking_csv}")
        sys.exit(1)
    
    if not Path(current_sbom_dir).exists():
        print(f"❌ Current SBOM directory not found: {current_sbom_dir}")
        sys.exit(1)
    
    if not Path(latest_sbom_dir).exists():
        print(f"❌ Latest SBOM directory not found: {latest_sbom_dir}")
        sys.exit(1)
    
    update_fixed_versions(tracking_csv, current_sbom_dir, latest_sbom_dir, output_csv)

if __name__ == "__main__":
    main()