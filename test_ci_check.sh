#!/bin/bash
# Test script to validate CI dependency check locally

set -e

echo "🔍 Checking for prohibited dependencies..."

# Check Go files for anchorlabsinc imports
echo "Checking .go files..."
FOUND_FILES=$(find . -name "*.go" -not -path "./.git/*" -exec grep -l "anchorlabsinc" {} \; 2>/dev/null)
if [ -n "$FOUND_FILES" ]; then
  echo "❌ ERROR: Found anchorlabsinc imports!"
  echo "$FOUND_FILES"
  exit 1
fi

# Check go.mod and go.sum for anchorlabsinc dependencies
echo "Checking go.mod and go.sum..."
if grep -q "anchorlabsinc" go.mod go.sum 2>/dev/null; then
  echo "❌ ERROR: Found anchorlabsinc in go.mod/go.sum!"
  grep "anchorlabsinc" go.mod go.sum 2>/dev/null
  exit 1
fi

echo "✅ No prohibited dependencies found"
echo ""
echo "Additional verification:"
echo "Go files checked:"
find . -name "*.go" -not -path "./.git/*" | wc -l
echo ""
echo "Total files containing 'anchorlabsinc' (for reference):"
grep -r "anchorlabsinc" . 2>/dev/null | grep -v ".git/" | wc -l
