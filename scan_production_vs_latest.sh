#!/usr/bin/env bash

# Source configuration functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config_functions.sh"

echo "=== Production vs Latest Vulnerability Analysis ==="
echo "This workflow scans:"
echo "1. Images currently RUNNING in production (AKS)"
echo "2. Corresponding LATEST images available for deployment (ACR)"
echo "3. Generates comparison reports to guide remediation decisions"
echo ""

# Authenticate with all ACR registries needed for production and dev environments
echo "=== Authenticating with ACR Registries ==="

# Authenticate production ACRs
if ! auth_acr_environment "prod"; then
  echo "❌ Failed to authenticate with production ACR registries"
  exit 1
fi

# Authenticate dev ACRs for accessing latest images
if ! auth_acr_environment "dev"; then
  echo "❌ Failed to authenticate with development ACR registries"
  exit 1
fi

echo ""

# Create organized output directories
mkdir -p sbom_reports/{production,latest,comparison}
mkdir -p reports/{production,latest,comparison}

echo "=== STEP 1: Scan Production Images (Currently Running in AKS) ==="
echo ""

PRODUCTION_IMAGES="reports/production_images.csv"
grep "^AKS," all_images_inventory.csv > "$PRODUCTION_IMAGES"

if [ ! -f "all_images_inventory.csv" ]; then
  echo "ERROR: all_images_inventory.csv not found"
  exit 1
fi

PROD_COUNT=$(grep -c . "$PRODUCTION_IMAGES" 2>/dev/null || echo "0")
echo "Found $PROD_COUNT production images to scan"
echo ""

CURRENT=0
SUCCESS_COUNT=0
ERROR_COUNT=0

while IFS=',' read -r SRC IMG; do
  ((CURRENT++))
  
  echo "[$CURRENT/$PROD_COUNT] PRODUCTION: $IMG"
  
  SAFE_NAME=$(echo "$IMG" | tr '/:' '__')
  OUTPUT_FILE="sbom_reports/production/${SAFE_NAME}.json"
  
  if [ -f "$OUTPUT_FILE" ]; then
    echo "  → Already scanned: $OUTPUT_FILE"
    ((SUCCESS_COUNT++))
  else
    echo "  → Scanning..."
    if trivy image --scanners vuln,license -q -f cyclonedx -o "$OUTPUT_FILE" "$IMG" 2>/dev/null; then
      echo "  → Success: $OUTPUT_FILE"
      ((SUCCESS_COUNT++))
    else
      echo "  → ERROR scanning $IMG (continuing with next image)"
      rm -f "$OUTPUT_FILE" 2>/dev/null
      ((ERROR_COUNT++))
    fi
  fi
  echo ""
done < "$PRODUCTION_IMAGES"

echo "Production scan summary:"
echo "  ✅ Success: $SUCCESS_COUNT images"
echo "  ❌ Errors:  $ERROR_COUNT images"
echo ""

if [ $SUCCESS_COUNT -eq 0 ]; then
  echo "❌ No production images were successfully scanned. Exiting."
  exit 1
fi

echo "=== STEP 2: Scan Latest ACR Images (Available for Deployment) ==="
echo ""

# Find corresponding :latest images for production repositories
LATEST_IMAGES="reports/latest_images.csv"
> "$LATEST_IMAGES"

while IFS=',' read -r SRC IMG; do
  # Extract repository name without tag
  REPO=$(echo "$IMG" | cut -d':' -f1)
  
  # Only process images from our subscription's ACR registries
  # Get list of ACR registries from production environment
  PROD_ACRS=""
  while IFS=':' read -r acr_name subscription registry_name; do
    if [ -n "$registry_name" ]; then
      PROD_ACRS="${PROD_ACRS}${registry_name}.azurecr.io|"
    fi
  done < <(get_acr_info "prod")
  
  # Remove trailing pipe and create pattern
  PROD_ACRS="${PROD_ACRS%|}"
  
  if [[ "$IMG" =~ ($PROD_ACRS) ]]; then
    # Check if we have a corresponding :latest image in the same ACR
    LATEST_IMG=$(grep "^ACR-.*,${REPO}:latest$" all_images_inventory.csv || true)
    
    if [ -n "$LATEST_IMG" ]; then
      echo "$LATEST_IMG" >> "$LATEST_IMAGES"
      echo "  ✅ Matched: $IMG → $(echo "$LATEST_IMG" | cut -d',' -f2)"
    else
      echo "  ⚠️  No :latest found for: $REPO"
    fi
  else
    echo "  ➡️  Skipping external image: $IMG (not in subscription ACRs)"
  fi
done < "$PRODUCTION_IMAGES"

LATEST_COUNT=$(grep -c . "$LATEST_IMAGES" 2>/dev/null || echo "0")
echo "Found $LATEST_COUNT corresponding :latest images to scan"
echo ""

if [ $LATEST_COUNT -eq 0 ]; then
  echo "⚠️  No :latest images found to scan. Skipping latest analysis."
else
  CURRENT=0
  SUCCESS_COUNT=0
  ERROR_COUNT=0
  
  while IFS=',' read -r SRC IMG; do
    ((CURRENT++))
    
    echo "[$CURRENT/$LATEST_COUNT] LATEST: $IMG"
    
    SAFE_NAME=$(echo "$IMG" | tr '/:' '__')
    OUTPUT_FILE="sbom_reports/latest/${SAFE_NAME}.json"
    
    if [ -f "$OUTPUT_FILE" ]; then
      echo "  → Already scanned: $OUTPUT_FILE"
      ((SUCCESS_COUNT++))
    else
      echo "  → Scanning..."
      if trivy image --scanners vuln,license -q -f cyclonedx -o "$OUTPUT_FILE" "$IMG" 2>/dev/null; then
        echo "  → Success: $OUTPUT_FILE"
        ((SUCCESS_COUNT++))
      else
        echo "  → ERROR scanning $IMG (continuing with next image)"
        rm -f "$OUTPUT_FILE" 2>/dev/null
        ((ERROR_COUNT++))
      fi
    fi
    echo ""
  done < "$LATEST_IMAGES"
  
  echo "Latest scan summary:"
  echo "  ✅ Success: $SUCCESS_COUNT images"
  echo "  ❌ Errors:  $ERROR_COUNT images"
  echo ""
fi

echo "=== STEP 3: Generate Comparison Analysis ==="
echo ""

# Generate tracking CSV for production images
echo "Analyzing production vulnerabilities..."
PROD_SBOM_COUNT=$(ls sbom_reports/production/*.json 2>/dev/null | wc -l | tr -d ' ')
if [ "$PROD_SBOM_COUNT" -gt 0 ]; then
  ./process_multiple_sboms.sh sbom_reports/production reports/production/vulnerabilities_tracking.csv
  python3 generate_summary.py reports/production/vulnerabilities_tracking.csv reports/production/vulnerabilities_summary.csv
  echo "  → Production analysis: reports/production/ ($PROD_SBOM_COUNT SBOMs processed)"
else
  echo "  ⚠️  No production SBOM files found to analyze"
fi

# Generate tracking CSV for latest images  
echo "Analyzing latest image vulnerabilities..."
LATEST_SBOM_COUNT=$(ls sbom_reports/latest/*.json 2>/dev/null | wc -l | tr -d ' ')
if [ "$LATEST_SBOM_COUNT" -gt 0 ]; then
  ./process_multiple_sboms.sh sbom_reports/latest reports/latest/vulnerabilities_tracking.csv
  python3 generate_summary.py reports/latest/vulnerabilities_tracking.csv reports/latest/vulnerabilities_summary.csv
  echo "  → Latest analysis: reports/latest/ ($LATEST_SBOM_COUNT SBOMs processed)"
else
  echo "  ⚠️  No latest SBOM files found to analyze"
fi

echo ""
echo "=== STEP 4: Generate Comparison Reports ==="
echo ""

if [ "$PROD_SBOM_COUNT" -gt 0 ] && [ "$LATEST_SBOM_COUNT" -gt 0 ]; then
  echo "Running vulnerability comparison analysis..."
  python3 compare_vulnerabilities.py
  echo ""
  
  echo "Generating detailed comparison CSV..."
  python3 generate_detailed_comparison.py
  echo ""
fi

echo "=== Analysis Complete! ==="
echo ""
echo "📊 Results Summary:"
echo "   Production SBOMs: $PROD_SBOM_COUNT files"
echo "   Latest SBOMs:     $LATEST_SBOM_COUNT files"
echo ""

if [ "$PROD_SBOM_COUNT" -gt 0 ] && [ "$LATEST_SBOM_COUNT" -gt 0 ]; then
  echo "📋 Generated Reports:"
  echo "1. reports/comparison/vulnerability_comparison_summary.txt - High-level comparison"
  echo "2. reports/comparison/detailed_vulnerability_comparison.csv - Package-level details"
  echo "3. reports/production/vulnerabilities_summary.csv - Production summary"
  echo "4. reports/latest/vulnerabilities_summary.csv - Latest summary"
  echo ""
  echo "📊 Generating Excel workbook for easier analysis..."
  if python3 generate_excel_comparison.py > /dev/null 2>&1; then
    echo "5. reports/vulnerability_comparison_analysis.xlsx - Interactive Excel analysis"
    echo ""
    echo "📊 Next Steps:"
    echo "1. Open the Excel file for interactive filtering and sorting"
    echo "2. Focus on packages marked as 'FIXED' for quick wins" 
    echo "3. Compare sheets side-by-side for update decisions"
  else
    echo ""
    echo "📊 Next Steps:"
    echo "1. Review the detailed comparison CSV for package-level decisions"
    echo "2. Focus on packages marked as 'FIXED' for quick wins"
    echo "3. Install 'pip install pandas openpyxl' for Excel export"
  fi
  echo ""
  echo "🎯 Comparison analysis complete!"
elif [ "$PROD_SBOM_COUNT" -gt 0 ]; then
  echo "📋 Production analysis available:"
  echo "1. Review: reports/production/vulnerabilities_summary.csv"
  echo "2. Consider scanning :latest images manually if needed"
else
  echo "⚠️  No vulnerability data available for analysis"
  echo "Check the error messages above and retry scanning"
fi
