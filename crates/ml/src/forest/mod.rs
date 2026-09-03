//! Tree-ensemble structure extracted from an ONNX model, and per-feature score
//! attribution over it.
//!
//! ## Why the structure is parsed at all
//!
//! Inference runs through onnxruntime (ADR-0002), which executes the graph as a black
//! box and returns only the score. The "explanations at detection time" commitment
//! (`docs/detection/ml.md`) needs the *walk*, not just the result — so this module
//! reads the tree structure back out of the model file itself: an `ai.onnx.ml`
//! `TreeEnsembleRegressor` node stores its trees as flat attribute arrays
//! (`nodes_featureids`, `nodes_values`, children, modes). skl2onnx emits one such
//! node per tree of an `IsolationForest`, fed through a `Gather` that selects input
//! columns, and pairs it with two `LabelEncoder`s mapping leaf id → path length and
//! leaf id → training-sample count; both that layout and a bare tree node are
//! supported.
//!
//! ## Attribution semantics
//!
//! Saabas-style path attribution over **effective depth**, the quantity the isolation
//! score is a monotone function of: a leaf's value is `depth + c(n)` where `n` is the
//! number of training samples that reached the leaf and `c` is sklearn's average
//! unbuilt-subtree path length — in a depth-capped tree, landing in a crowded leaf is
//! effectively deep and landing in a lonely one is effectively shallow, and dropping
//! `c(n)` loses most of the signal. Every internal node is assigned the
//! sample-count-weighted expectation of the leaf values below it (the expected
//! effective depth of a random *training* point under that node); as an input walks
//! the tree, each split moves that expectation and the move is charged to the split's
//! feature. Per tree the decomposition telescopes exactly:
//! `leaf value = root expectation + Σ moves`. Ensemble values are averaged over trees
//! and **negated**, so a positive contribution pushes toward anomalous (isolation
//! forests isolate anomalies *shallow*).
//!
//! Models without the sample-count `LabelEncoder` fall back to uniform leaf weights
//! and no `c(n)` term (pure structural depth).
//!
//! The Python reference (`ml/tests/attribution_reference.py`) implements the same
//! definition; the two are pinned against each other by
//! `tests/fixtures/attribution_golden.json`.

mod onnx;

use onnx::{build_trees, find_graph, leaf_encoders, parse_graph, resolve_column_mapping};

/// Model files come from the update channel; parsing must fail closed and loudly.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("model file truncated")]
    Truncated,
    #[error("malformed protobuf: {0}")]
    Malformed(&'static str),
    #[error("unsupported model shape: {0}")]
    Unsupported(&'static str),
    #[error("inconsistent tree structure: {0}")]
    Inconsistent(&'static str),
}

#[derive(Debug, Clone)]
pub(crate) enum NodeKind {
    /// `x[feature] <= threshold` takes the true child; NaN takes the false child
    /// (models with `nodes_missing_value_tracks_true` set are rejected).
    Branch {
        feature: usize,
        threshold: f32,
        true_child: u32,
        false_child: u32,
    },
    Leaf,
}

#[derive(Debug, Clone)]
pub(crate) struct TreeNode {
    pub(crate) kind: NodeKind,
    /// Sample-count-weighted expected effective depth of the leaves under this node
    /// (module docs). For a leaf: `depth + c(n_samples)`. Precomputed at parse time.
    pub(crate) expected: f64,
}

#[derive(Debug)]
pub(crate) struct Tree {
    /// Indexed by node id; node 0 is the root (validated at parse time).
    pub(crate) nodes: Vec<TreeNode>,
}

/// A parsed tree ensemble, ready for attribution walks.
#[derive(Debug)]
pub struct Forest {
    trees: Vec<Tree>,
    n_features: usize,
}

/// One input's per-feature attribution (see module docs for the semantics).
#[derive(Debug, Clone)]
pub struct Attribution {
    /// Indexed by original input feature. Positive pushes toward anomalous.
    /// `expected_depth - depth == contributions.iter().sum()` up to float error.
    pub contributions: Vec<f64>,
    /// Effective depth of this input, averaged over trees.
    pub depth: f64,
    /// Ensemble baseline: expected effective depth of a training point.
    pub expected_depth: f64,
}

/// sklearn's `_average_path_length`: expected path length of an unbuilt subtree
/// holding `n` samples (Euler–Mascheroni constant, harmonic approximation).
pub(crate) fn average_path_length(n: f64) -> f64 {
    const EULER_GAMMA: f64 = 0.577_215_664_901_532_9;
    if n <= 1.0 {
        0.0
    } else if n == 2.0 {
        1.0
    } else {
        2.0 * ((n - 1.0).ln() + EULER_GAMMA) - 2.0 * (n - 1.0) / n
    }
}

impl Forest {
    /// Parses the tree structure (and per-leaf sample counts where present) out of a
    /// serialized ONNX model.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the bytes are not a parseable ONNX graph or the
    /// graph does not contain the expected `TreeEnsembleRegressor` structure.
    pub fn from_onnx_bytes(model: &[u8]) -> Result<Self, ParseError> {
        let graph = find_graph(model)?;
        let parsed = parse_graph(graph)?;

        let mut trees = Vec::new();
        let mut n_features = 0usize;
        for ensemble in &parsed.tree_nodes {
            let mapping = resolve_column_mapping(ensemble, &parsed)?;
            let encoders = leaf_encoders(ensemble, &parsed)?;
            build_trees(
                ensemble,
                mapping.as_deref(),
                &encoders,
                &mut trees,
                &mut n_features,
            )?;
        }
        if trees.is_empty() {
            return Err(ParseError::Unsupported(
                "no TreeEnsembleRegressor node in graph",
            ));
        }
        Ok(Forest { trees, n_features })
    }

    /// Number of input features the ensemble reads (highest referenced index + 1).
    #[must_use]
    pub fn n_features(&self) -> usize {
        self.n_features
    }

    #[must_use]
    pub fn n_trees(&self) -> usize {
        self.trees.len()
    }

    /// Walks every tree with `x` and returns the per-feature attribution.
    ///
    /// `x` must have at least [`Forest::n_features`] values (extra values are
    /// ignored, matching how a model reads only the columns it was trained on).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Inconsistent`] when `x` is shorter than the model's
    /// feature space.
    pub fn attribute(&self, x: &[f32]) -> Result<Attribution, ParseError> {
        if x.len() < self.n_features {
            return Err(ParseError::Inconsistent(
                "input shorter than the feature space",
            ));
        }
        let mut contributions = vec![0.0f64; self.n_features];
        let mut depth_sum = 0.0f64;
        let mut expected_sum = 0.0f64;

        for tree in &self.trees {
            expected_sum += tree.nodes[0].expected;
            let mut current = 0usize;
            loop {
                let node = &tree.nodes[current];
                match node.kind {
                    NodeKind::Leaf => {
                        depth_sum += node.expected;
                        break;
                    }
                    NodeKind::Branch {
                        feature,
                        threshold,
                        true_child,
                        false_child,
                    } => {
                        // NaN compares false and takes the false branch, matching
                        // ONNX semantics with missing_value_tracks_true unset.
                        let next = if x[feature] <= threshold {
                            true_child as usize
                        } else {
                            false_child as usize
                        };
                        contributions[feature] += tree.nodes[next].expected - node.expected;
                        current = next;
                    }
                }
            }
        }

        let n = self.trees.len() as f64;
        for c in &mut contributions {
            // Negate: moving *shallower* than expected is what makes an input
            // anomalous, and positive must mean "pushes toward anomalous".
            *c = -*c / n;
        }
        Ok(Attribution {
            contributions,
            depth: depth_sum / n,
            expected_depth: expected_sum / n,
        })
    }
}

/// The top-k attributions by absolute contribution, paired with the feature values
/// the model saw — ready to attach to a `schema::detection::Detection`.
#[must_use]
pub fn top_attributions(
    attribution: &Attribution,
    x: &[f32],
    feature_names: &[&str],
    k: usize,
) -> Vec<schema::detection::ScoreAttribution> {
    let mut order: Vec<usize> = (0..attribution.contributions.len()).collect();
    order.sort_by(|&a, &b| {
        attribution.contributions[b]
            .abs()
            .total_cmp(&attribution.contributions[a].abs())
    });
    order
        .into_iter()
        .take(k)
        .filter_map(|i| {
            Some(schema::detection::ScoreAttribution {
                feature: (*feature_names.get(i)?).to_string(),
                value: f64::from(*x.get(i)?),
                contribution: attribution.contributions[i],
            })
        })
        .collect()
}
