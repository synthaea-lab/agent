//! ONNX graph walking: extracting the `TreeEnsembleRegressor` structure (nodes,
//! column mapping, leaf encoders, per-leaf sample counts) out of the serialized
//! model. Consumed only by [`super::Forest::from_onnx_bytes`]; the walk and the
//! attribution semantics live in the parent module.

use crate::proto::{Reader, Wire, read_f32s, read_i64s};

use super::{NodeKind, ParseError, Tree, TreeNode, average_path_length};

/// A `NodeProto` reduced to what we read.
pub(super) struct GraphNode<'a> {
    op_type: &'a [u8],
    inputs: Vec<&'a [u8]>,
    outputs: Vec<&'a [u8]>,
    attributes: Vec<&'a [u8]>,
}

pub(super) struct ParsedGraph<'a> {
    pub(super) tree_nodes: Vec<GraphNode<'a>>,
    other_nodes: Vec<GraphNode<'a>>,
    /// INT64 initializers by name (only kind we need: `Gather` column indices).
    int_initializers: Vec<(&'a [u8], Vec<i64>)>,
    input_names: Vec<&'a [u8]>,
}

impl<'a> ParsedGraph<'a> {
    fn producer_of(&self, name: &[u8]) -> Option<&GraphNode<'a>> {
        self.other_nodes
            .iter()
            .find(|n| n.outputs.first() == Some(&name))
    }

    fn consumers_of(&self, name: &[u8]) -> impl Iterator<Item = &GraphNode<'a>> {
        self.other_nodes
            .iter()
            .filter(move |n| n.inputs.contains(&name))
    }
}

/// `ModelProto.graph` is field 7.
pub(super) fn find_graph(model: &[u8]) -> Result<&[u8], ParseError> {
    let mut reader = Reader::new(model);
    let mut graph = None;
    while !reader.done() {
        let (field, wire) = reader.tag()?;
        if field == 7 && wire == Wire::Len {
            graph = Some(reader.bytes()?);
        } else {
            reader.skip(wire)?;
        }
    }
    graph.ok_or(ParseError::Malformed("model has no graph"))
}

/// `GraphProto`: node = 1, initializer = 5, input = 11.
pub(super) fn parse_graph(graph: &[u8]) -> Result<ParsedGraph<'_>, ParseError> {
    let mut parsed = ParsedGraph {
        tree_nodes: Vec::new(),
        other_nodes: Vec::new(),
        int_initializers: Vec::new(),
        input_names: Vec::new(),
    };
    let mut reader = Reader::new(graph);
    while !reader.done() {
        let (field, wire) = reader.tag()?;
        match (field, wire) {
            (1, Wire::Len) => {
                let node = parse_node(reader.bytes()?)?;
                if node.op_type == b"TreeEnsembleRegressor" {
                    parsed.tree_nodes.push(node);
                } else {
                    parsed.other_nodes.push(node);
                }
            }
            (5, Wire::Len) => {
                if let Some(entry) = parse_int64_initializer(reader.bytes()?)? {
                    parsed.int_initializers.push(entry);
                }
            }
            (11, Wire::Len) => {
                // ValueInfoProto.name = 1.
                let mut inner = Reader::new(reader.bytes()?);
                while !inner.done() {
                    let (f, w) = inner.tag()?;
                    if f == 1 && w == Wire::Len {
                        parsed.input_names.push(inner.bytes()?);
                    } else {
                        inner.skip(w)?;
                    }
                }
            }
            _ => reader.skip(wire)?,
        }
    }
    Ok(parsed)
}

/// `NodeProto`: input = 1, output = 2, `op_type` = 4, attribute = 5.
fn parse_node(node: &[u8]) -> Result<GraphNode<'_>, ParseError> {
    let mut parsed = GraphNode {
        op_type: b"",
        inputs: Vec::new(),
        outputs: Vec::new(),
        attributes: Vec::new(),
    };
    let mut reader = Reader::new(node);
    while !reader.done() {
        let (field, wire) = reader.tag()?;
        match (field, wire) {
            (1, Wire::Len) => parsed.inputs.push(reader.bytes()?),
            (2, Wire::Len) => parsed.outputs.push(reader.bytes()?),
            (4, Wire::Len) => parsed.op_type = reader.bytes()?,
            (5, Wire::Len) => parsed.attributes.push(reader.bytes()?),
            _ => reader.skip(wire)?,
        }
    }
    Ok(parsed)
}

/// An INT64 initializer: (tensor name, values).
type Int64Initializer<'a> = (&'a [u8], Vec<i64>);

/// `TensorProto`: `data_type` = 2, `int64_data` = 7, name = 8, `raw_data` = 9.
/// Returns `Some((name, values))` for INT64 tensors, `None` for every other type.
fn parse_int64_initializer(tensor: &[u8]) -> Result<Option<Int64Initializer<'_>>, ParseError> {
    const INT64: u64 = 7;
    let mut name: &[u8] = b"";
    let mut data_type = 0u64;
    let mut values = Vec::new();
    let mut raw: Option<&[u8]> = None;
    let mut reader = Reader::new(tensor);
    while !reader.done() {
        let (field, wire) = reader.tag()?;
        match (field, wire) {
            (2, Wire::Varint) => data_type = reader.varint()?,
            (7, _) => read_i64s(&mut values, &mut reader, wire)?,
            (8, Wire::Len) => name = reader.bytes()?,
            (9, Wire::Len) => raw = Some(reader.bytes()?),
            _ => reader.skip(wire)?,
        }
    }
    if data_type != INT64 {
        return Ok(None);
    }
    if values.is_empty()
        && let Some(raw) = raw
    {
        if raw.len() % 8 != 0 {
            return Err(ParseError::Malformed("INT64 raw_data not 8-aligned"));
        }
        values.extend(
            raw.chunks_exact(8)
                .map(|c| i64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]])),
        );
    }
    Ok(Some((name, values)))
}

/// Maps a tree node's feature ids back to original input columns.
///
/// skl2onnx feeds each `TreeEnsembleRegressor` through a `Gather(X, indices)`; the
/// indices initializer is the column mapping. A tree node reading the graph input
/// directly maps identically (`None`).
pub(super) fn resolve_column_mapping<'a>(
    ensemble: &GraphNode<'a>,
    graph: &ParsedGraph<'a>,
) -> Result<Option<Vec<i64>>, ParseError> {
    let source = *ensemble
        .inputs
        .first()
        .ok_or(ParseError::Malformed("tree node with no input"))?;
    if graph.input_names.contains(&source) {
        return Ok(None);
    }
    let producer = graph.producer_of(source).ok_or(ParseError::Unsupported(
        "tree input produced by no known node",
    ))?;
    if producer.op_type != b"Gather" {
        return Err(ParseError::Unsupported(
            "tree input produced by a node other than Gather",
        ));
    }
    let indices_name = *producer
        .inputs
        .get(1)
        .ok_or(ParseError::Malformed("Gather with no indices input"))?;
    let indices = graph
        .int_initializers
        .iter()
        .find(|(name, _)| *name == indices_name)
        .map(|(_, v)| v.clone())
        .ok_or(ParseError::Unsupported(
            "Gather indices are not an initializer",
        ))?;
    Ok(Some(indices))
}

/// A `LabelEncoder` keyed by leaf node id.
pub(super) struct LeafEncoder {
    keys: Vec<i64>,
    values: Vec<f32>,
}

/// Finds the `LabelEncoder`s hanging off a tree node's output (via `Cast`):
/// skl2onnx's `IsolationForest` converter emits one mapping leaf id → path length and
/// one mapping leaf id → training-sample count. Which is which is decided later
/// against the actual tree structure ([`pick_sample_counts`]) — never by node name.
pub(super) fn leaf_encoders(
    ensemble: &GraphNode<'_>,
    graph: &ParsedGraph<'_>,
) -> Result<Vec<LeafEncoder>, ParseError> {
    let mut encoders = Vec::new();
    let Some(output) = ensemble.outputs.first() else {
        return Ok(encoders);
    };
    for cast in graph.consumers_of(output) {
        if cast.op_type != b"Cast" {
            continue;
        }
        let Some(cast_out) = cast.outputs.first() else {
            continue;
        };
        for enc in graph.consumers_of(cast_out) {
            if enc.op_type != b"LabelEncoder" {
                continue;
            }
            let mut keys = Vec::new();
            let mut values = Vec::new();
            for raw in &enc.attributes {
                let (name, ints, floats, _) = parse_attribute(raw)?;
                match name {
                    b"keys_int64s" => keys = ints,
                    b"values_floats" => values = floats,
                    _ => {}
                }
            }
            if keys.len() != values.len() {
                return Err(ParseError::Inconsistent(
                    "LabelEncoder key/value length mismatch",
                ));
            }
            encoders.push(LeafEncoder { keys, values });
        }
    }
    Ok(encoders)
}

// ── Tree construction ─────────────────────────────────────────────────────────

#[derive(Default)]
struct TreeAttrs {
    tree_ids: Vec<i64>,
    node_ids: Vec<i64>,
    feature_ids: Vec<i64>,
    values: Vec<f32>,
    modes: Vec<Vec<u8>>,
    true_ids: Vec<i64>,
    false_ids: Vec<i64>,
    missing_tracks_true: Vec<i64>,
}

/// `AttributeProto`: name = 1, floats = 7, ints = 8, strings = 9.
type Attribute<'a> = (&'a [u8], Vec<i64>, Vec<f32>, Vec<Vec<u8>>);

fn parse_attribute(raw: &[u8]) -> Result<Attribute<'_>, ParseError> {
    let mut name: &[u8] = b"";
    let mut ints = Vec::new();
    let mut floats = Vec::new();
    let mut strings = Vec::new();
    let mut reader = Reader::new(raw);
    while !reader.done() {
        let (field, wire) = reader.tag()?;
        match (field, wire) {
            (1, Wire::Len) => name = reader.bytes()?,
            (7, _) => read_f32s(&mut floats, &mut reader, wire)?,
            (8, _) => read_i64s(&mut ints, &mut reader, wire)?,
            (9, Wire::Len) => strings.push(reader.bytes()?.to_vec()),
            _ => reader.skip(wire)?,
        }
    }
    Ok((name, ints, floats, strings))
}

fn parse_tree_attrs(ensemble: &GraphNode<'_>) -> Result<TreeAttrs, ParseError> {
    let mut attrs = TreeAttrs::default();
    for raw in &ensemble.attributes {
        let (name, ints, floats, strings) = parse_attribute(raw)?;
        match name {
            b"nodes_treeids" => attrs.tree_ids = ints,
            b"nodes_nodeids" => attrs.node_ids = ints,
            b"nodes_featureids" => attrs.feature_ids = ints,
            b"nodes_values" => attrs.values = floats,
            b"nodes_modes" => attrs.modes = strings,
            b"nodes_truenodeids" => attrs.true_ids = ints,
            b"nodes_falsenodeids" => attrs.false_ids = ints,
            b"nodes_missing_value_tracks_true" => attrs.missing_tracks_true = ints,
            _ => {}
        }
    }
    Ok(attrs)
}

pub(super) fn build_trees(
    ensemble: &GraphNode<'_>,
    mapping: Option<&[i64]>,
    encoders: &[LeafEncoder],
    trees: &mut Vec<Tree>,
    n_features: &mut usize,
) -> Result<(), ParseError> {
    let attrs = parse_tree_attrs(ensemble)?;
    let n = attrs.node_ids.len();
    if n == 0 {
        return Err(ParseError::Inconsistent("tree node with no tree nodes"));
    }
    if [
        attrs.tree_ids.len(),
        attrs.feature_ids.len(),
        attrs.values.len(),
        attrs.modes.len(),
        attrs.true_ids.len(),
        attrs.false_ids.len(),
    ]
    .iter()
    .any(|&len| len != n)
    {
        return Err(ParseError::Inconsistent(
            "node attribute arrays disagree in length",
        ));
    }
    if attrs.missing_tracks_true.iter().any(|&v| v != 0) {
        return Err(ParseError::Unsupported("missing_value_tracks_true is set"));
    }

    // One TreeEnsembleRegressor can hold several trees (contiguous runs of
    // nodes_treeids); skl2onnx's IsolationForest emits one tree per node, and only
    // that layout carries leaf encoders (their keys are ids in a single tree).
    // The Gather mapping is the model's input contract: it sets the feature-space
    // width even when no tree happens to split on the last columns, so contribution
    // vectors stay aligned with the extracted feature vector.
    if let Some(map) = mapping {
        *n_features = (*n_features).max(map.len());
    }

    let multi_tree = attrs.tree_ids.iter().any(|&t| t != attrs.tree_ids[0]);
    let encoders: &[LeafEncoder] = if multi_tree { &[] } else { encoders };

    let mut start = 0usize;
    while start < n {
        let tree_id = attrs.tree_ids[start];
        let mut end = start;
        while end < n && attrs.tree_ids[end] == tree_id {
            end += 1;
        }
        trees.push(build_one_tree(
            &attrs,
            start..end,
            mapping,
            encoders,
            n_features,
        )?);
        start = end;
    }
    Ok(())
}

fn build_one_tree(
    attrs: &TreeAttrs,
    range: core::ops::Range<usize>,
    mapping: Option<&[i64]>,
    encoders: &[LeafEncoder],
    n_features: &mut usize,
) -> Result<Tree, ParseError> {
    let count = range.len();
    let mut nodes = vec![None; count];
    for i in range.clone() {
        let node_id = usize::try_from(attrs.node_ids[i])
            .map_err(|_| ParseError::Inconsistent("negative node id"))?;
        if node_id >= count {
            return Err(ParseError::Inconsistent("node id outside the tree"));
        }
        let kind = match attrs.modes[i].as_slice() {
            b"LEAF" => NodeKind::Leaf,
            b"BRANCH_LEQ" => {
                let raw_feature = attrs.feature_ids[i];
                let column = match mapping {
                    Some(map) => *usize::try_from(raw_feature)
                        .ok()
                        .and_then(|f| map.get(f))
                        .ok_or(ParseError::Inconsistent(
                            "feature id outside Gather mapping",
                        ))?,
                    None => raw_feature,
                };
                let feature = usize::try_from(column)
                    .map_err(|_| ParseError::Inconsistent("negative feature column"))?;
                *n_features = (*n_features).max(feature + 1);
                let child = |id: i64| {
                    u32::try_from(id)
                        .ok()
                        .filter(|&c| (c as usize) < count)
                        .ok_or(ParseError::Inconsistent("child id outside the tree"))
                };
                NodeKind::Branch {
                    feature,
                    threshold: attrs.values[i],
                    true_child: child(attrs.true_ids[i])?,
                    false_child: child(attrs.false_ids[i])?,
                }
            }
            _ => return Err(ParseError::Unsupported("branch mode other than BRANCH_LEQ")),
        };
        if nodes[node_id].is_some() {
            return Err(ParseError::Inconsistent("duplicate node id"));
        }
        nodes[node_id] = Some(TreeNode {
            kind,
            expected: 0.0,
        });
    }
    let mut nodes: Vec<TreeNode> = nodes
        .into_iter()
        .collect::<Option<_>>()
        .ok_or(ParseError::Inconsistent("node ids are not dense"))?;

    let (depth, post_order) = walk_structure(&nodes)?;
    let counts = pick_sample_counts(&nodes, &depth, encoders)?;
    compute_expectations(&mut nodes, &depth, &post_order, counts.as_deref());
    Ok(Tree { nodes })
}

/// Depth of every node plus a parent-before-children visit order, validating that
/// the child pointers form a tree rooted at node 0 (each node reached exactly once).
fn walk_structure(nodes: &[TreeNode]) -> Result<(Vec<u32>, Vec<usize>), ParseError> {
    let count = nodes.len();
    let mut depth = vec![u32::MAX; count];
    let mut order = Vec::with_capacity(count);
    let mut stack = vec![0usize];
    depth[0] = 0;
    while let Some(current) = stack.pop() {
        order.push(current);
        if let NodeKind::Branch {
            true_child,
            false_child,
            ..
        } = nodes[current].kind
        {
            for child in [true_child as usize, false_child as usize] {
                if depth[child] != u32::MAX {
                    return Err(ParseError::Inconsistent("node reachable twice (cycle)"));
                }
                depth[child] = depth[current] + 1;
                stack.push(child);
            }
        }
    }
    if order.len() != count {
        return Err(ParseError::Inconsistent("unreachable nodes in tree"));
    }
    Ok((depth, order))
}

/// Decides which leaf encoder holds training-sample counts — structurally, never by
/// name: the path-length encoder is the one whose value is `depth + 1` for every
/// leaf; the sample-count one is the other (positive integers). `None` when the
/// model ships no encoders (fallback semantics, module docs).
fn pick_sample_counts(
    nodes: &[TreeNode],
    depth: &[u32],
    encoders: &[LeafEncoder],
) -> Result<Option<Vec<f64>>, ParseError> {
    if encoders.is_empty() {
        return Ok(None);
    }
    let is_path_length = |enc: &LeafEncoder| {
        enc.keys.iter().zip(&enc.values).all(|(&k, &v)| {
            usize::try_from(k)
                .ok()
                .and_then(|k| depth.get(k))
                .is_some_and(|&d| v == (d + 1) as f32)
        })
    };
    let candidates: Vec<&LeafEncoder> = encoders.iter().filter(|e| !is_path_length(e)).collect();
    let [counts_encoder] = candidates.as_slice() else {
        return Err(ParseError::Inconsistent(
            "cannot identify the sample-count leaf encoder",
        ));
    };

    let mut counts = vec![f64::NAN; nodes.len()];
    for (&key, &value) in counts_encoder.keys.iter().zip(&counts_encoder.values) {
        let id = usize::try_from(key)
            .ok()
            .filter(|&k| k < nodes.len())
            .ok_or(ParseError::Inconsistent(
                "leaf encoder key outside the tree",
            ))?;
        if !matches!(nodes[id].kind, NodeKind::Leaf) {
            return Err(ParseError::Inconsistent("leaf encoder key is not a leaf"));
        }
        if value < 1.0 || value.fract() != 0.0 {
            return Err(ParseError::Inconsistent(
                "sample count is not a positive integer",
            ));
        }
        counts[id] = f64::from(value);
    }
    for (i, node) in nodes.iter().enumerate() {
        if matches!(node.kind, NodeKind::Leaf) && counts[i].is_nan() {
            return Err(ParseError::Inconsistent("leaf without a sample count"));
        }
    }
    Ok(Some(counts))
}

/// Fills every node's expectation (module docs). With sample counts: leaf value is
/// `depth + c(n)`, weights are counts. Without: leaf value is `depth`, weights 1.
fn compute_expectations(
    nodes: &mut [TreeNode],
    depth: &[u32],
    parent_first: &[usize],
    counts: Option<&[f64]>,
) {
    let mut weight = vec![0.0f64; nodes.len()];
    for &i in parent_first.iter().rev() {
        // Children were pushed after their parent, so the reverse order sees
        // children before parents.
        match nodes[i].kind {
            NodeKind::Leaf => {
                let n = counts.map_or(1.0, |c| c[i]);
                weight[i] = n;
                nodes[i].expected = f64::from(depth[i])
                    + if counts.is_some() {
                        average_path_length(n)
                    } else {
                        0.0
                    };
            }
            NodeKind::Branch {
                true_child,
                false_child,
                ..
            } => {
                let (t, f) = (true_child as usize, false_child as usize);
                weight[i] = weight[t] + weight[f];
                nodes[i].expected =
                    (weight[t] * nodes[t].expected + weight[f] * nodes[f].expected) / weight[i];
            }
        }
    }
}
