#!/usr/bin/env python3
"""
Extract OS version information from existing SBOM files.
Much faster than running Trivy again - just parses existing JSON files.
"""

import json
import os
import sys
import csv
import glob
from typing import Dict, Any, List, Optional
from pathlib import Path
import argparse

def extract_os_from_sbom(sbom_file_path: str) -> Optional[Dict[str, Any]]:
    """Extract OS information from a CycloneDX SBOM file."""
    try:
        with open(sbom_file_path, 'r') as f:
            sbom_data = json.load(f)
        
        # Extract image name from metadata
        image_name = "unknown"
        if 'metadata' in sbom_data and 'component' in sbom_data['metadata']:
            image_name = sbom_data['metadata']['component'].get('name', 'unknown')
        
        # Find operating-system component
        components = sbom_data.get('components', [])
        for component in components:
            if component.get('type') == 'operating-system':
                os_name = component.get('name', 'unknown')
                os_version = component.get('version', 'unknown')
                
                # Try to determine EOSL status (this would need more sophisticated logic)
                # For now, we'll set it as unknown since SBOM doesn't typically include EOSL
                eosl = 'unknown'
                
                return {
                    'image': image_name,
                    'os_family': os_name,
                    'os_version': os_version,
                    'eosl': eosl,
                    'sbom_file': os.path.basename(sbom_file_path)
                }
        
        # If no operating-system component found
        return {
            'image': image_name,
            'os_family': 'unknown',
            'os_version': 'unknown',
            'eosl': 'unknown',
            'sbom_file': os.path.basename(sbom_file_path)
        }
        
    except Exception as e:
        print(f"Error processing {sbom_file_path}: {str(e)}", file=sys.stderr)
        return None

def find_sbom_files(directory: str, pattern: str = "*.json") -> List[str]:
    """Find all SBOM files in a directory."""
    search_pattern = os.path.join(directory, pattern)
    files = glob.glob(search_pattern)
    return sorted(files)

def process_sbom_directory(directory: str) -> List[Dict[str, Any]]:
    """Process all SBOM files in a directory."""
    sbom_files = find_sbom_files(directory)
    
    if not sbom_files:
        print(f"No SBOM files found in {directory}")
        return []
    
    print(f"Processing {len(sbom_files)} SBOM files from {directory}...")
    
    results = []
    for i, sbom_file in enumerate(sbom_files, 1):
        print(f"[{i}/{len(sbom_files)}] Processing: {os.path.basename(sbom_file)}")
        
        os_info = extract_os_from_sbom(sbom_file)
        if os_info:
            results.append(os_info)
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Extract OS information from SBOM files')
    parser.add_argument('--directory', '-d', help='Directory containing SBOM files')
    parser.add_argument('--file', '-f', help='Single SBOM file to process')
    parser.add_argument('--csv', '-c', help='Output CSV file')
    parser.add_argument('--all-dirs', '-a', action='store_true', 
                       help='Process all subdirectories in sbom_reports/')
    
    args = parser.parse_args()
    
    results = []
    
    if args.all_dirs:
        # Process all directories in sbom_reports/
        sbom_base = "sbom_reports"
        if not os.path.exists(sbom_base):
            print(f"Error: {sbom_base} directory not found")
            sys.exit(1)
        
        for subdir in os.listdir(sbom_base):
            subdir_path = os.path.join(sbom_base, subdir)
            if os.path.isdir(subdir_path):
                print(f"\n=== Processing {subdir} ===")
                subdir_results = process_sbom_directory(subdir_path)
                results.extend(subdir_results)
    
    elif args.directory:
        if not os.path.exists(args.directory):
            print(f"Error: Directory {args.directory} not found")
            sys.exit(1)
        
        results = process_sbom_directory(args.directory)
    
    elif args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            sys.exit(1)
        
        print(f"Processing single file: {args.file}")
        os_info = extract_os_from_sbom(args.file)
        if os_info:
            results.append(os_info)
    
    else:
        parser.print_help()
        sys.exit(1)
    
    if not results:
        print("No OS information extracted")
        sys.exit(1)
    
    # Output results
    if args.csv:
        # Create output directory if needed
        output_dir = os.path.dirname(args.csv)
        if output_dir:  # Only create directory if there is one
            os.makedirs(output_dir, exist_ok=True)
        
        # Write to CSV
        with open(args.csv, 'w', newline='') as f:
            fieldnames = ['image', 'os_family', 'os_version', 'eosl', 'sbom_file']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        
        print(f"✅ Results written to {args.csv}")
    else:
        # Print to stdout
        print("\n" + "="*100)
        print("OS Information Summary:")
        print("="*100)
        
        for info in results:
            eosl_status = "⚠️  EOSL" if info['eosl'] == True else "✅ Supported" if info['eosl'] == False else "❓ Unknown"
            print(f"{info['image']:<50} | {info['os_family']:<10} | {info['os_version']:<15} | {eosl_status}")
    
    print(f"\n📊 Summary: Extracted OS info from {len(results)} SBOM files")
    
    # Print OS family distribution
    os_families = {}
    for result in results:
        family = result['os_family']
        os_families[family] = os_families.get(family, 0) + 1
    
    print("\n📊 OS Family Distribution:")
    for family, count in sorted(os_families.items()):
        print(f"  {family}: {count} images")

if __name__ == '__main__':
    main()
