#!/usr/bin/env python3
"""
Optimized script to extract OS version information from container images using Trivy.
Uses parallelization and minimal scanning for maximum performance.
"""

import json
import os
import subprocess
import sys
import csv
import concurrent.futures
from typing import Dict, Any, List
from pathlib import Path

def get_image_os_info(image_name: str) -> Dict[str, Any]:
    """Extract OS information from a container image using Trivy (optimized)."""
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

def scan_images_parallel(images: List[str], max_workers: int = 4) -> List[Dict[str, Any]]:
    """Scan multiple images in parallel for better performance."""
    results = []
    
    print(f"Scanning {len(images)} images in parallel (max {max_workers} workers)...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_image = {executor.submit(get_image_os_info, image): image for image in images}
        
        # Process completed tasks
        for i, future in enumerate(concurrent.futures.as_completed(future_to_image), 1):
            image = future_to_image[future]
            print(f"[{i}/{len(images)}] Completed: {image}")
            
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as exc:
                print(f"Error processing {image}: {exc}", file=sys.stderr)
    
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_os_versions_optimized.py <image1> [image2] ...")
        print("   or: python3 get_os_versions_optimized.py --file <images_list.txt>")
        print("   or: python3 get_os_versions_optimized.py --csv <output.csv> <image1> [image2] ...")
        print("   or: python3 get_os_versions_optimized.py --csv <output.csv> --file <images_list.txt>")
        print("   or: python3 get_os_versions_optimized.py --workers <N> --csv <output.csv> --file <images_list.txt>")
        print("")
        print("Options:")
        print("  --workers N    Number of parallel workers (default: 4)")
        sys.exit(1)
    
    images = []
    output_csv = None
    max_workers = 4
    
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
        elif args[i] == '--workers':
            if i + 1 >= len(args):
                print("Error: --workers requires a number", file=sys.stderr)
                sys.exit(1)
            try:
                max_workers = int(args[i + 1])
                if max_workers < 1:
                    raise ValueError("Workers must be >= 1")
            except ValueError as e:
                print(f"Error: Invalid worker count: {e}", file=sys.stderr)
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
    
    # Scan images in parallel
    results = scan_images_parallel(images, max_workers)
    
    # Output results
    if output_csv:
        # Write to CSV
        with open(output_csv, 'w', newline='') as f:
            if results:
                fieldnames = ['image', 'os_family', 'os_version', 'eosl']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        print(f"✅ Results written to {output_csv}")
    else:
        # Print to stdout
        print("\nResults:")
        print("-" * 80)
        for info in results:
            eosl_status = "⚠️  EOSL" if info['eosl'] else "✅ Supported"
            print(f"{info['image']:<50} | {info['os_family']:<10} | {info['os_version']:<15} | {eosl_status}")
    
    print(f"\n📊 Summary: Processed {len(results)}/{len(images)} images successfully")

if __name__ == '__main__':
    main()
