#!/usr/bin/env bash

SBOM_DIR="$1"
OUTPUT_CSV="$2"

if [ -z "$SBOM_DIR" ] || [ -z "$OUTPUT_CSV" ]; then
  echo "Usage: $0 <sbom_directory> <output_csv>"
  echo "Example: $0 sbom_reports/production reports/production/vulnerabilities_tracking.csv"
  exit 1
fi

if [ ! -d "$SBOM_DIR" ]; then
  echo "Error: Directory $SBOM_DIR not found"
  exit 1
fi

echo "🔄 Processing SBOM files in: $SBOM_DIR"
echo "📊 Output CSV: $OUTPUT_CSV"
echo ""

# Create output directory if it doesn't exist
mkdir -p "$(dirname "$OUTPUT_CSV")"

# Create temporary directory for individual CSVs
TEMP_DIR=$(mktemp -d)
echo "Using temp directory: $TEMP_DIR"

SBOM_COUNT=0
SUCCESS_COUNT=0

# Process each SBOM file individually
for SBOM_FILE in "$SBOM_DIR"/*.json; do
  if [ ! -f "$SBOM_FILE" ]; then
    echo "No SBOM files found in $SBOM_DIR"
    exit 1
  fi
  
  ((SBOM_COUNT++))
  
  BASENAME=$(basename "$SBOM_FILE" .json)
  TEMP_CSV="$TEMP_DIR/${BASENAME}.csv"
  
  echo "[$SBOM_COUNT] Processing: $BASENAME"
  
  if python3 generate_remediation_csv.py "$SBOM_FILE" "$TEMP_CSV" >/dev/null 2>&1; then
    ((SUCCESS_COUNT++))
    echo "  ✅ Success"
  else
    echo "  ❌ Failed"
  fi
done

echo ""
echo "📈 Processed $SUCCESS_COUNT/$SBOM_COUNT SBOM files successfully"

if [ $SUCCESS_COUNT -eq 0 ]; then
  echo "❌ No SBOM files were processed successfully"
  rm -rf "$TEMP_DIR"
  exit 1
fi

# Combine all CSV files into one
echo ""
echo "🔗 Combining CSV files..."

FIRST_FILE=true
for CSV_FILE in "$TEMP_DIR"/*.csv; do
  if [ ! -f "$CSV_FILE" ]; then
    continue
  fi
  
  if [ "$FIRST_FILE" = true ]; then
    # Include header from first file
    cat "$CSV_FILE" > "$OUTPUT_CSV"
    FIRST_FILE=false
  else
    # Skip header for subsequent files
    tail -n +2 "$CSV_FILE" >> "$OUTPUT_CSV"
  fi
done

# Clean up
rm -rf "$TEMP_DIR"

if [ -f "$OUTPUT_CSV" ]; then
  TOTAL_ROWS=$(tail -n +2 "$OUTPUT_CSV" | wc -l | tr -d ' ')
  echo "✅ Combined CSV created: $OUTPUT_CSV"
  echo "📊 Total vulnerability entries: $TOTAL_ROWS"
else
  echo "❌ Failed to create combined CSV"
  exit 1
fi
