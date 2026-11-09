# ml

On-device machine learning for the agent: feature extraction from `schema` events and
Isolation Forest scoring through ONNX Runtime ([`ort`](https://crates.io/crates/ort)).
The models are trained, calibrated and exported by
[synthaea-lab/ml](https://github.com/synthaea-lab/ml) and loaded from disk at start-up; a
missing or invalid model leaves the agent running without ML evidence.

| Tier | Scorer | Scores | Used by the agent |
| --- | --- | --- | --- |
| T0 | `CmdlineScorer` | one command line | not yet |
| T1 | `BehaviorScorer` | one process incarnation | not yet |
| T2 | `CorrelationScorer` | one process's correlator window, as evidence for the correlator's belief | yes, when a model is present |

Each score can carry a per-feature attribution. Tiers, features, attribution and the
degraded modes are documented in [docs/detection/ml.md](../../docs/detection/ml.md).

## Feature parity

Every feature extractor under [`src/features`](src/features.rs) mirrors a Python definition in
the training pipeline. A model scores correctly only if both sides build the same vector for
the same input, so each extractor is pinned by a golden fixture that both repositories test
against. Change a feature on both sides in step, and retrain the model.

## ONNX Runtime linking

The default `dynamic-onnx` feature downloads a prebuilt ONNX Runtime, which keeps
development builds fast. Packaged builds use `--no-default-features` and link ONNX Runtime
1.30.0 statically, so the agent ships as one binary with no shared library to load.

Static build on Linux or macOS:

```sh
./packaging/toolchain/build-onnxruntime-static.sh
export ORT_LIB_LOCATION="$PWD/onnxruntime/build/Linux/Release"   # on macOS: build/MacOS/Release
eval "$(./packaging/toolchain/ort-static-link-flags.sh)"
cargo test -p ml --release --no-default-features
```

Static build on Windows (MSVC), from PowerShell:

```powershell
.\packaging\toolchain\build-onnxruntime-static.ps1
$env:ORT_LIB_LOCATION = "$PWD\onnxruntime\build\Windows\Release\Release"
.\packaging\toolchain\ort-static-link-flags.ps1 | Invoke-Expression
cargo test -j 1 -p ml --release --no-default-features
```

Prerequisites, build times and platform notes are in
[onnxruntime-static-build.md](../../packaging/toolchain/onnxruntime-static-build.md) and
[onnxruntime-static-build-macos.md](../../packaging/toolchain/onnxruntime-static-build-macos.md).

## Testing

```sh
cargo test -p ml
```

The integration tests score the fixture models in [`tests/fixtures/`](tests/fixtures) and
compare features, scores and attributions with golden files produced by the Python pipeline.
The fixture models are trained on synthetic data: they prove that Rust and Python agree, not
how well a model detects. Some golden tests read fixtures from a checkout of
[synthaea-lab/ml](https://github.com/synthaea-lab/ml) next to this repository and skip
without it.
