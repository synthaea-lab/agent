#!/bin/bash
# Verification script for Issue #46 implementation

echo "=========================================="
echo "Issue #46 Implementation Verification"
echo "=========================================="
echo ""

echo "Phase 1: Python Conformal Calibration"
echo "--------------------------------------"
echo "✓ Calibration module:"
ls -lh ml/synthaea_ml/calibration/calibrate_conformal.py 2>/dev/null && echo "  - calibrate_conformal.py exists" || echo "  ✗ MISSING"
echo ""
echo "✓ Training scripts updated:"
grep -q "calibrate_threshold" ml/synthaea_ml/training/train_linux.py && echo "  - train_linux.py ✓" || echo "  ✗ train_linux.py missing"
grep -q "calibrate_threshold" ml/synthaea_ml/training/train_windows.py && echo "  - train_windows.py ✓" || echo "  ✗ train_windows.py missing"
echo ""
echo "✓ Schema extended:"
grep -q "SCHEMA_VERSION = 3" ml/synthaea_ml/registry/training_record.py && echo "  - TrainingRecord schema v3 ✓" || echo "  ✗ Schema not updated"
echo ""

echo "Phase 2: Rust OOD Guards"
echo "------------------------"
echo "✓ Bounds module:"
ls -lh crates/ml/src/bounds.rs 2>/dev/null && echo "  - bounds.rs exists" || echo "  ✗ MISSING"
echo ""
echo "✓ Scorer updates:"
grep -q "FeatureOutOfBounds" crates/ml/src/scorer.rs && echo "  - ScorerError extended ✓" || echo "  ✗ ScorerError missing"
grep -q "from_onnx_bytes_with_metadata" crates/ml/src/scorer.rs && echo "  - Metadata loading ✓" || echo "  ✗ Metadata loading missing"
echo ""

echo "Phase 3: Documentation"
echo "----------------------"
ls -lh PHASE3_INTEGRATION.md 2>/dev/null && echo "✓ Phase 3 integration guide exists" || echo "✗ MISSING"
echo ""

echo "Tests"
echo "-----"
echo "Running Python tests..."
cd ml && python -m pytest tests/test_calibrate_conformal.py -v --tb=short 2>&1 | tail -5
cd ..
echo ""

echo "Rust build..."
cargo check -p ml --lib 2>&1 | grep -E "(Finished|error)" | head -1

echo ""
echo "=========================================="
echo "Verification Complete"
echo "=========================================="
