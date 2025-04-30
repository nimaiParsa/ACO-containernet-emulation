#!/bin/bash

# === INPUT ARGUMENTS ===
PROB_THRESHOLD="$1"     # e.g., 0.8 means 80% chance to generate >0.9 density
OUTPUT_FILE="$2"        # e.g., output.bin
FILE_SIZE="$3"          # e.g., 1048576 (1 MB)

# === VALIDATION ===
if [[ -z "$PROB_THRESHOLD" || -z "$OUTPUT_FILE" || -z "$FILE_SIZE" ]]; then
  echo "Usage: $0 <probability_threshold> <output_file> <file_size_bytes>"
  echo "Example: $0 0.8 output.bin 1048576"
  exit 1
fi

# === GENERATE RANDOM FLOAT BETWEEN 0 AND 1 ===
rand_float=$(awk -v r1=$RANDOM -v r2=$RANDOM 'BEGIN { srand(); print (r1 * 32768 + r2) / 1073741824 }')

# === DETERMINE DENSITY RANGE BASED ON THRESHOLD ===
if (( $(echo "$rand_float <= $PROB_THRESHOLD" | bc -l) )); then
    # Generate density > 0.9
    density=$(awk 'BEGIN { srand(); print 0.900001 + (rand() * (1.0 - 0.900001)) }')
else
    # Generate density < 0.9
    density=$(awk 'BEGIN { srand(); print rand() * 0.9 }')
fi

# === CALCULATE BYTE COUNTS ===
rand_bytes=$(awk -v s=$FILE_SIZE -v d=$density 'BEGIN { printf "%d", s * d }')
zero_bytes=$((FILE_SIZE - rand_bytes))

# === GENERATE FILE CONTENT ===
dd if=/dev/urandom bs=1 count="$rand_bytes" status=none > "$OUTPUT_FILE"
dd if=/dev/zero bs=1 count="$zero_bytes" status=none >> "$OUTPUT_FILE"

# === SHUFFLE CONTENT ===
tmpfile=$(mktemp)
fold -w1 "$OUTPUT_FILE" | shuf | tr -d '\n' > "$tmpfile"
mv "$tmpfile" "$OUTPUT_FILE"

# === REPORT ===
echo "Generated $OUTPUT_FILE"
echo "Approx. density: $density"
