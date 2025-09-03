#!/usr/bin/env bash
set -euo pipefail

echo "=== Production Image Vulnerability Scanner ==="
echo "This script scans all images in the production inventory for vulnerabilities"
echo ""

# Create output directory
mkdir -p sbom_reports
echo "Created sbom_reports directory"

# Counter for progress tracking
TOTAL=$(tail -n +2 all_images_inventory.csv | grep -c . || echo "0")
CURRENT=0

echo "Processing $TOTAL images..."
echo ""

# Read CSV and scan each image
tail -n +2 all_images_inventory.csv | while IFS=',' read -r SRC IMG; do
  # Skip empty lines
  [ -z "$IMG" ] && continue
  
  ((CURRENT++)) || true
  
  echo "[$CURRENT/$TOTAL] Scanning: $IMG (from $SRC)"
  
  # Create safe filename
  SAFE_NAME=$(echo "$IMG" | tr '/:' '__')
  OUTPUT_FILE="sbom_reports/${SAFE_NAME}.json"
  
  # Skip if already exists
  if [ -f "$OUTPUT_FILE" ]; then
    echo "  → Skipping (already exists): $OUTPUT_FILE"
    continue
  fi
  
  # Run Trivy scan
  if trivy image --scanners vuln,license -q -f cyclonedx -o "$OUTPUT_FILE" "$IMG"; then
    echo "  → Success: $OUTPUT_FILE"
  else
    echo "  → ERROR scanning $IMG - continuing with next image"
    # Remove failed output file if it exists
    rm -f "$OUTPUT_FILE"
  fi
  
  echo ""
done

echo "=== Scan Complete ==="
echo "SBOM files generated in: sbom_reports/"
echo "Total files: $(ls sbom_reports/*.json 2>/dev/null | wc -l | tr -d ' ')"
echo ""
echo "Next steps:"
echo "1. Run your existing analysis scripts on the SBOM files"
echo "2. Generate CSV reports with: python3 generate_remediation_csv.py sbom_reports/*.json"
echo "3. Create summaries with: python3 generate_summary.py"
