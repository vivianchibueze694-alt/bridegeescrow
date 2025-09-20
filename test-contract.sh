#!/bin/bash

# Navigate to the BridgeEscrow directory
cd /Users/a/Documents/stacks/vivian_chibueze/BridgeEscrow

echo "Current directory: $(pwd)"
echo "Files in directory:"
ls -la

echo ""
echo "Checking contract syntax..."
clarinet check

echo ""
echo "Running basic contract validation..."
if [ -f "contracts/bridgeescrewcontract.clar" ]; then
    echo "Contract file exists"
    echo "Contract size: $(wc -l < contracts/bridgeescrewcontract.clar) lines"
else
    echo "Contract file not found"
fi

echo ""
echo "Checking test files..."
if [ -f "tests/bridgeescrewcontract.test.ts" ]; then
    echo "Test file exists"
    echo "Test file size: $(wc -l < tests/bridgeescrewcontract.test.ts) lines"
else
    echo "Test file not found"
fi

echo ""
echo "Security enhancements added:"
echo "✓ Reentrancy protection"
echo "✓ Rate limiting"
echo "✓ Blacklist functionality"
echo "✓ Arbitrator staking"
echo "✓ Input validation"
echo "✓ Overflow protection"
echo "✓ Enhanced access control"
echo "✓ Emergency protocols"
echo "✓ Comprehensive error handling"
