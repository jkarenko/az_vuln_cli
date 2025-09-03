#!/usr/bin/env python3
"""
Simple script to extract OS version information from container images using Trivy.
No vulnerability scanning - just OS detection.
"""

import json
import os
import subprocess
import sys
import csv
from typing import Dict, Any

def get_image_os_info(image_name: str) -> Dict[str, Any]:
    """Extract OS information from a container image using Trivy."""
    try:
        # Optimized Trivy command - no vulnerability scanning needed for OS detection
        cmd = [
            'trivy', 'image', 
            '--format', 'json',
            '--scanners', '',  # Empty scanners - just get metadata!
            '--quiet',
            '--skip-version-check',  # Skip version check notices
            image_name
        ]
        
        # Reduced timeout since we're not doing vulnerability scanning
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            print(f"Error scanning {image_name}: {result.stderr}", file=sys.stderr)
            return None
            
        data = json.loads(result.stdout)
        
        if 'Metadata' in data and 'OS' in data['Metadata']:
            os_info = data['Metadata']['OS']
            return {
                'image': image_name,
                'os_family': os_info.get('Family', 'unknown'),
                'os_version': os_info.get('Name', 'unknown'),
                'eosl': os_info.get('EOSL', False)  # End of Service Life
            }
        else:
            return {
                'image': image_name,
                'os_family': 'unknown',
                'os_version': 'unknown', 
                'eosl': 'unknown'
            }
            
    except subprocess.TimeoutExpired:
        print(f"Timeout scanning {image_name}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error scanning {image_name}: {str(e)}", file=sys.stderr)
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_os_versions.py <image1> [image2] ...")
        print("   or: python3 get_os_versions.py --file <images_list.txt>")
        print("   or: python3 get_os_versions.py --csv <output.csv> <image1> [image2] ...")
        print("   or: python3 get_os_versions.py --csv <output.csv> --file <images_list.txt>")
        sys.exit(1)
    
    images = []
    output_csv = None
    
    # Parse arguments more carefully
    args = sys.argv[1:]
    i = 0
    
    while i < len(args):
        if args[i] == '--csv':
            if i + 1 >= len(args):
                print("Error: --csv requires a filename", file=sys.stderr)
                sys.exit(1)
            output_csv = args[i + 1]
            i += 2
        elif args[i] == '--file':
            if i + 1 >= len(args):
                print("Error: --file requires a filename", file=sys.stderr)
                sys.exit(1)
            filename = args[i + 1]
            try:
                with open(filename, 'r') as f:
                    images.extend([line.strip() for line in f if line.strip()])
            except FileNotFoundError:
                print(f"Error: File {filename} not found", file=sys.stderr)
                sys.exit(1)
            i += 2
        else:
            images.append(args[i])
            i += 1
    
    if not images:
        print("Error: No images specified", file=sys.stderr)
        sys.exit(1)
    
    # Create output directory early if CSV output is requested
    if output_csv:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        print(f"📊 Output will be saved to: {output_csv}")
    
    results = []
    
    print(f"Scanning {len(images)} images for OS information...")
    
    for i, image in enumerate(images, 1):
        print(f"[{i}/{len(images)}] Scanning {image}...")
        os_info = get_image_os_info(image)
        if os_info:
            results.append(os_info)
    
    # Output results
    if output_csv:
        # Write to CSV
        with open(output_csv, 'w', newline='') as f:
            if results:
                fieldnames = ['image', 'os_family', 'os_version', 'eosl']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        print(f"Results written to {output_csv}")
    else:
        # Print to stdout
        print("\nResults:")
        print("-" * 80)
        for info in results:
            eosl_status = "⚠️  EOSL" if info['eosl'] else "✅ Supported"
            print(f"{info['image']:<50} | {info['os_family']:<10} | {info['os_version']:<15} | {eosl_status}")

if __name__ == '__main__':
    main()