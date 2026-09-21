# ML Crate

On-device ML inference using ONNX Runtime with feature extraction from event streams.

## ONNX Runtime Linking

Per **ADR-0002 decision #2**, onnxruntime is statically linked into the agent binary for:
- Single-binary deployment (no runtime .so/.dll dependencies)
- Updater integrity guarantees
- Root/SYSTEM execution security posture

### Default Build (Dynamic Linking - Development)

For development builds, the `ort` crate can use dynamic libraries if explicitly enabled:

```bash
# Not recommended - violates ADR-0002
cargo build -p ml --features ort/download-binaries
```

**Note:** The workspace `ort` dependency has `default-features = false`, so dynamic linking must be explicitly opted into. Do not commit changes that re-enable `download-binaries` or `copy-dylibs`.

### Static Linking (Production - Required)

**Issue:** #110 tracks full integration. Current status: **Manual setup required**

#### Quick Start

```bash
# 1. Build onnxruntime from source
./lab/provisioning/build-onnxruntime-static.sh

# 2. Set environment variable
export ORT_LIB_LOCATION="$PWD/onnxruntime/build/Linux/Release"

# 3. Generate static link flags
eval "$(./lab/provisioning/ort-static-link-flags.sh)"

# 4. Build and test
cargo test -p ml --release

# 5. Verify no runtime dependencies
ldd target/release/deps/ml-* | grep -i onnx  # Should return nothing
```

#### Detailed Documentation

See `lab/provisioning/onnxruntime-static-build.md` for:
- Prerequisites and platform support
- Detailed build steps
- Known issues and workarounds
- CI integration options (TODO)

#### Platform Support

- ✅ **Linux (Ubuntu 24.04+)**: Fully tested, production-ready
- ⏳ **Windows**: Not yet implemented (issue #110)
- ⏳ **macOS**: Not yet implemented (issue #110)

## Features

### Inference

- ONNX model loading and inference
- Feature vector extraction from event streams
- Correlation scoring
- Capture scoring (process tree analysis)

### Event Integration

- Consumes events from `schema::Event`
- Integrates with `correlator` for event windowing
- Produces scored detections

## Testing

```bash
# Run all ml tests
cargo test -p ml

# Run specific test suites
cargo test -p ml --test correlation_scorer  # End-to-end correlation scoring
cargo test -p ml --test capture_parity      # Python parity validation
```

### Test Coverage

- **Unit tests**: Feature extraction, vector building
- **Integration tests**: End-to-end inference with real ONNX models
- **Parity tests**: Validates Rust feature extraction matches Python training pipeline

## Development

### Adding New Features

1. Define feature in both:
   - Rust: `src/features.rs`
   - Python: `ml/features.py` (training pipeline)

2. Add parity test case to maintain feature consistency

3. Update test fixtures if schema changes

### Model Updates

Models are located in `tests/fixtures/`:
- `correlation_scorer.onnx` - Correlation detection model
- `capture_scorer.onnx` - Process tree analysis model

Regenerate models when:
- Feature definitions change
- Training data updates
- Model architecture changes

Coordinate with ML workstream for model regeneration.

## Dependencies

- `ort`: ONNX Runtime bindings (statically linked per ADR-0002)
- `schema`: Event type definitions
- `correlator`: Event windowing and aggregation
- `thiserror`: Error handling

## Known Issues

### Static Linking Not Automated (Issue #110)

**Status:** Manual setup required (see Static Linking section above)

**Root causes:**
1. `ort-sys` v2.0.0-rc.13 has incomplete static library list for onnxruntime 1.30.0 (~78 missing abseil libraries)
2. `re2` library is orphaned CMake target in static-only builds (Ubuntu/glibc)

**Workarounds:** Automated via `build-onnxruntime-static.sh` and `ort-static-link-flags.sh`

**Upstream:** Consider filing issues with:
- pykeio/ort: Incomplete library list in `ort-sys/build/static_link/mod.rs`
- microsoft/onnxruntime: `re2` CMake dependency not expressed in build graph

### Binary Size Impact

**TODO:** Measure and document binary size delta (ADR-0002 §3)

## References

- Issue #110: ML crate static linking tracking
- ADR-0002: ML runtime decisions (static linking requirement)
- `lab/provisioning/onnxruntime-static-build.md`: Detailed static build guide
