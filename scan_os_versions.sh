#!/bin/bash
# Simple OS version scanner for container images.
# Much faster than full vulnerability scanning - only extracts OS information.

set -e

# Default output file
OUTPUT_FILE="os_versions_$(date +%Y%m%d_%H%M%S).csv"

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -f, --file FILE        Read image names from file (one per line)"
    echo "  -o, --output FILE      Output CSV file (default: os_versions_TIMESTAMP.csv)"
    echo "  -h, --help             Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 -f aks_running_images.txt"
    echo "  $0 -f acr_images.txt -o acr_os_versions.csv"
    echo "  $0 alpine:3.15 ubuntu:20.04"
    echo ""
    echo "Available image inventory files:"
    for file in *_images.txt; do
        if [[ -f "$file" ]]; then
            count=$(grep -c . "$file" 2>/dev/null || echo "0")
            echo "  - $file ($count images)"
        fi
    done
}

# Parse command line arguments
IMAGES=()
INPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            INPUT_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            IMAGES+=("$1")
            shift
            ;;
    esac
done

# Validate inputs
if [[ -n "$INPUT_FILE" && ${#IMAGES[@]} -gt 0 ]]; then
    echo "Error: Cannot specify both --file and individual images"
    exit 1
fi

if [[ -z "$INPUT_FILE" && ${#IMAGES[@]} -eq 0 ]]; then
    echo "Error: Must specify either --file or individual images"
    show_help
    exit 1
fi

if [[ -n "$INPUT_FILE" && ! -f "$INPUT_FILE" ]]; then
    echo "Error: File '$INPUT_FILE' not found"
    exit 1
fi

# Run the scan
echo "🔍 Starting OS version scan..."
echo "📊 Output will be saved to: $OUTPUT_FILE"
echo ""

if [[ -n "$INPUT_FILE" ]]; then
    echo "📁 Reading images from: $INPUT_FILE"
    python3 get_os_versions.py --csv "$OUTPUT_FILE" --file "$INPUT_FILE"
else
    echo "🐳 Scanning ${#IMAGES[@]} specified images"
    python3 get_os_versions.py --csv "$OUTPUT_FILE" "${IMAGES[@]}"
fi

echo ""
echo "✅ Scan complete!"
echo "📄 Results saved to: $OUTPUT_FILE"

# Show summary if output file exists
if [[ -f "$OUTPUT_FILE" ]]; then
    echo ""
    echo "📊 Quick Summary:"
    echo "   Total images: $(tail -n +2 "$OUTPUT_FILE" | grep -c . || echo "0")"
    echo "   OS Families:"
    tail -n +2 "$OUTPUT_FILE" | cut -d',' -f2 | sort | uniq -c | while read count family; do
        echo "     - $family: $count images"
    done
    echo ""
    echo "⚠️  EOSL Images:"
    if tail -n +2 "$OUTPUT_FILE" | grep -q ",true$"; then
        tail -n +2 "$OUTPUT_FILE" | grep ",true$" | cut -d',' -f1 | sed 's/^/     - /'
    else
        echo "     None found ✅"
    fi
fi