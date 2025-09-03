#!/usr/bin/env python3
"""
Fast OS version extraction - uses existing SBOM files when available,
falls back to optimized Trivy scanning only when needed.
"""

import os
import sys
import glob
from pathlib import Path
import subprocess

def get_sbom_file_for_image(image_name: str, sbom_dir: str = "sbom_reports") -> str:
    """Find SBOM file for a given image name."""
    # Convert image name to safe filename format (same as used in scanning scripts)
    safe_name = image_name.replace('/', '__').replace(':', '__')
    
    # Look in all subdirectories of sbom_reports
    pattern = f"{sbom_dir}/**/{safe_name}.json"
    matches = glob.glob(pattern, recursive=True)
    
    if matches:
        return matches[0]  # Return first match
    return None

def main():
    if len(sys.argv) < 2:
        print("Fast OS Information Extractor")
        print("=============================")
        print("")
        print("Usage:")
        print("  python3 get_os_info_fast.py <image1> [image2] ...")
        print("  python3 get_os_info_fast.py --from-sboms <sbom_directory>")
        print("  python3 get_os_info_fast.py --all-sboms")
        print("")
        print("Examples:")
        print("  # Extract from existing SBOMs (fastest)")
        print("  python3 get_os_info_fast.py --all-sboms")
        print("  python3 get_os_info_fast.py --from-sboms sbom_reports/production")
        print("")
        print("  # Mixed approach (SBOM if available, Trivy if not)")
        print("  python3 get_os_info_fast.py alpine:3.19 ubuntu:22.04")
        print("")
        print("Speed comparison:")
        print("  📁 SBOM-based extraction: ~0.01 seconds per image")
        print("  🏃 Optimized Trivy:       ~3-5 seconds per image")
        print("  🐌 Original Trivy (vuln): ~15-30 seconds per image")
        sys.exit(1)
    
    if sys.argv[1] == "--all-sboms":
        # Process all SBOM files
        print("🚀 Using SBOM-based extraction (fastest method)")
        subprocess.run([
            "python3", "extract_os_from_sboms.py", 
            "--all-dirs"
        ])
    
    elif sys.argv[1] == "--from-sboms":
        if len(sys.argv) < 3:
            print("Error: --from-sboms requires a directory")
            sys.exit(1)
        
        sbom_dir = sys.argv[2]
        print(f"🚀 Using SBOM-based extraction from {sbom_dir}")
        subprocess.run([
            "python3", "extract_os_from_sboms.py", 
            "--directory", sbom_dir
        ])
    
    else:
        # Process individual images - use SBOM if available, Trivy if not
        images = sys.argv[1:]
        
        sbom_available = []
        trivy_needed = []
        
        # Check which images have SBOM files
        for image in images:
            sbom_file = get_sbom_file_for_image(image)
            if sbom_file and os.path.exists(sbom_file):
                sbom_available.append((image, sbom_file))
            else:
                trivy_needed.append(image)
        
        print(f"📊 Analysis: {len(sbom_available)} images have SBOMs, {len(trivy_needed)} need Trivy scanning")
        print("")
        
        # Process SBOM files first (fastest)
        if sbom_available:
            print("🚀 Extracting from existing SBOMs...")
            for image, sbom_file in sbom_available:
                print(f"  📁 {image} → {sbom_file}")
                subprocess.run([
                    "python3", "extract_os_from_sboms.py", 
                    "--file", sbom_file
                ])
            print("")
        
        # Use optimized Trivy for remaining images
        if trivy_needed:
            print("🏃 Running optimized Trivy scans for remaining images...")
            cmd = ["python3", "get_os_versions.py"] + trivy_needed
            subprocess.run(cmd)

if __name__ == '__main__':
    main()
