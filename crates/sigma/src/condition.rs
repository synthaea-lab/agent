//! The bounded condition grammar (#978): boolean expressions over the named blocks of a rule's
//! `detection`, parsed and checked once at load time, evaluated per event with nothing allocated
//! for the event.
//!
//! ```text
//! expr    := or
//! or      := and ( "or" and )*
//! and     := not ( "and" not )*
//! not     := "not" not | atom
//! atom    := "(" expr ")" | quant | NAME
//! quant   := ( "1" | "all" ) "of" ( "them" | PATTERN )
//! ```
//!
//! Precedence is `not` over `and` over `or`. `NAME` is a block of the rule's `detection` (there
//! is no special `selection`); `PATTERN` is a block name, or a name prefix ending in one `*`;
//! `them` is every block. Keywords are case-insensitive, names are not. A pattern is expanded at
//! load time into the blocks it matches, and **one that matches no block is a load error**, never
//! an empty (vacuously true or false) match.
//!
//! Everything else is refused at load with a message naming it: aggregations (`count()`,
//! `near`, a `|` pipe), `N of` for any N but 1, `any of`, a `*` anywhere but at the end of a
//! pattern, a reference to a block that does not exist, a keyword where a name belongs, and any
//! character outside names, parentheses and whitespace. A rule never loads and then silently
//! never matches (#11).
//!
//! **Bounds**, all checked before evaluation: the condition is at most [`MAX_CONDITION_BYTES`]
//! bytes and [`MAX_TOKENS`] tokens, nests parentheses and `not`s at most [`MAX_DEPTH`] deep (the
//! parser's recursion is capped by it), and refers to at most [`MAX_BLOCKS`] distinct blocks.
//! Evaluation short-circuits and evaluates each block at most once per event (a fixed array on
//! the stack indexed by block), so its cost is the sum of the referenced blocks' costs whatever
//! the size of the expression.

use std::collections::HashMap;

use crate::rule::Selection;

/// Longest condition text accepted, in bytes.
pub(crate) const MAX_CONDITION_BYTES: usize = 1024;
/// Most tokens (names, keywords, parentheses) in one condition.
pub(crate) const MAX_TOKENS: usize = 128;
/// Deepest nesting of parentheses and `not` in one condition.
pub(crate) const MAX_DEPTH: usize = 8;
/// Most distinct blocks one condition may refer to, directly or through `of`.
pub(crate) const MAX_BLOCKS: usize = 64;

/// A parsed condition: the expression and the blocks it refers to, in the order the expression
/// indexes them.
#[derive(Debug)]
pub(crate) struct Compiled {
    expr: Expr,
    /// Names of the referenced blocks; `Expr` holds indices into this list.
    pub(crate) blocks: Vec<String>,
}

#[derive(Debug)]
enum Expr {
    Block(usize),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    /// `1 of ...`: any of the blocks.
    AnyOf(Vec<usize>),
    /// `all of ...`: every one of the blocks.
    AllOf(Vec<usize>),
}

/// Parses `condition` against the rule's blocks (`detection`'s keys, minus the condition and the
/// timeframe), refusing anything outside the grammar and every bound that is exceeded.
///
/// # Errors
///
/// A message naming what is unsupported or wrong, for [`crate::SigmaError::Unsupported`].
pub(crate) fn compile(
    condition: &str,
    available: &HashMap<String, Selection>,
) -> Result<Compiled, String> {
    let condition = condition.trim();
    if condition.is_empty() {
        return Err("the condition is empty".to_string());
    }
    if condition.len() > MAX_CONDITION_BYTES {
        return Err(format!(
            "the condition is longer than {MAX_CONDITION_BYTES} bytes"
        ));
    }
    let tokens = tokenize(condition)?;
    let mut names: Vec<&str> = available.keys().map(String::as_str).collect();
    names.sort_unstable();
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
        available: &names,
        referenced: Vec::new(),
    };
    let expr = parser.parse_or(0)?;
    if let Some(token) = parser.peek() {
        return Err(format!("unexpected `{token}` after a complete expression"));
    }
    if parser.referenced.len() > MAX_BLOCKS {
        return Err(format!(
            "the condition refers to {} blocks (at most {MAX_BLOCKS})",
            parser.referenced.len()
        ));
    }
    Ok(Compiled {
        expr,
        blocks: parser.referenced.into_iter().map(str::to_owned).collect(),
    })
}

impl Compiled {
    /// Whether the condition holds, given what each referenced block does on the event.
    /// `block(index)` evaluates the block `self.blocks[index]`; it is called at most once per
    /// block.
    pub(crate) fn eval(&self, mut block: impl FnMut(usize) -> bool) -> bool {
        let mut memo = [None; MAX_BLOCKS];
        eval_expr(&self.expr, &mut memo, &mut block)
    }
}

fn eval_expr(
    expr: &Expr,
    memo: &mut [Option<bool>; MAX_BLOCKS],
    block: &mut impl FnMut(usize) -> bool,
) -> bool {
    let mut one = |index: usize, memo: &mut [Option<bool>; MAX_BLOCKS]| -> bool {
        *memo[index].get_or_insert_with(|| block(index))
    };
    match expr {
        Expr::Block(index) => one(*index, memo),
        Expr::Not(inner) => !eval_expr(inner, memo, block),
        Expr::And(terms) => terms.iter().all(|term| eval_expr(term, memo, block)),
        Expr::Or(terms) => terms.iter().any(|term| eval_expr(term, memo, block)),
        Expr::AnyOf(indices) => indices.iter().any(|&index| one(index, memo)),
        Expr::AllOf(indices) => indices.iter().all(|&index| one(index, memo)),
    }
}

/// Splits on whitespace, with `(` and `)` as tokens of their own, and refuses any character that
/// is not part of a name, a pattern or a keyword. The token cap is applied while splitting, so a
/// hostile condition is cut off before it is parsed.
fn tokenize(condition: &str) -> Result<Vec<&str>, String> {
    let mut tokens = Vec::new();
    let mut start = None;
    for (at, c) in condition.char_indices() {
        let separator = c.is_whitespace() || c == '(' || c == ')';
        if separator {
            if let Some(from) = start.take() {
                push_token(&mut tokens, &condition[from..at])?;
            }
            if c == '(' || c == ')' {
                push_token(&mut tokens, &condition[at..at + 1])?;
            }
        } else if start.is_none() {
            start = Some(at);
        }
    }
    if let Some(from) = start {
        push_token(&mut tokens, &condition[from..])?;
    }
    Ok(tokens)
}

fn push_token<'a>(tokens: &mut Vec<&'a str>, token: &'a str) -> Result<(), String> {
    if let Some(unsupported) = unsupported_token(token) {
        return Err(unsupported);
    }
    if tokens.len() == MAX_TOKENS {
        return Err(format!("the condition has more than {MAX_TOKENS} tokens"));
    }
    tokens.push(token);
    Ok(())
}

/// The refusal for a token that cannot be part of the grammar, naming what it is.
fn unsupported_token(token: &str) -> Option<String> {
    if token.contains('|') {
        return Some(format!(
            "`{token}`: a pipe (aggregation such as `| count()`) is not supported"
        ));
    }
    if ["count", "near"]
        .iter()
        .any(|word| token.eq_ignore_ascii_case(word))
    {
        return Some(format!(
            "`{token}`: aggregations (`count()`, `near`, ...) are not supported"
        ));
    }
    let name_char = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | '*' | '.');
    if token != "(" && token != ")" && !token.chars().all(name_char) {
        return Some(format!(
            "`{token}`: only block names, `*`, `and`, `or`, `not`, `1 of`, `all of`, `them` and parentheses are supported"
        ));
    }
    None
}

struct Parser<'a> {
    tokens: &'a [&'a str],
    at: usize,
    /// The rule's block names, sorted.
    available: &'a [&'a str],
    /// Blocks referenced so far, in first-use order (`Expr` indexes into this).
    referenced: Vec<&'a str>,
}

const KEYWORDS: [&str; 6] = ["and", "or", "not", "of", "all", "them"];

fn is_keyword(token: &str) -> bool {
    KEYWORDS.iter().any(|k| token.eq_ignore_ascii_case(k))
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.at).copied()
    }

    fn peek_is(&self, keyword: &str) -> bool {
        self.peek().is_some_and(|t| t.eq_ignore_ascii_case(keyword))
    }

    fn next(&mut self) -> Option<&'a str> {
        let token = self.peek();
        self.at += 1;
        token
    }

    /// `depth` counts the parentheses and `not`s entered; it is what bounds the recursion.
    fn parse_or(&mut self, depth: usize) -> Result<Expr, String> {
        let mut terms = vec![self.parse_and(depth)?];
        while self.peek_is("or") {
            self.at += 1;
            terms.push(self.parse_and(depth)?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Expr::Or(terms)
        })
    }

    fn parse_and(&mut self, depth: usize) -> Result<Expr, String> {
        let mut terms = vec![self.parse_not(depth)?];
        while self.peek_is("and") {
            self.at += 1;
            terms.push(self.parse_not(depth)?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Expr::And(terms)
        })
    }

    fn parse_not(&mut self, depth: usize) -> Result<Expr, String> {
        if self.peek_is("not") {
            self.at += 1;
            let depth = enter(depth)?;
            return Ok(Expr::Not(Box::new(self.parse_not(depth)?)));
        }
        self.parse_atom(depth)
    }

    fn parse_atom(&mut self, depth: usize) -> Result<Expr, String> {
        let Some(token) = self.next() else {
            return Err("the condition ends where an operand is expected".to_string());
        };
        if token == "(" {
            let depth = enter(depth)?;
            let inner = self.parse_or(depth)?;
            return match self.next() {
                Some(")") => Ok(inner),
                Some(other) => Err(format!("expected `)` and found `{other}`")),
                None => Err("a `(` is never closed".to_string()),
            };
        }
        if token == ")" {
            return Err("a `)` closes nothing".to_string());
        }
        // `min(`, `max(`, `avg(`, `sum(`: aggregation functions. A bare `min` is a block name.
        if self.peek() == Some("(")
            && ["min", "max", "avg", "sum"]
                .iter()
                .any(|word| token.eq_ignore_ascii_case(word))
        {
            return Err(format!(
                "`{token}(`: aggregations (`count()`, `min()`, `near`, ...) are not supported"
            ));
        }
        if self.peek_is("of") {
            return self.parse_quantifier(token);
        }
        if is_keyword(token) {
            return Err(format!("`{token}` where a block name is expected"));
        }
        if token.contains('*') {
            return Err(format!(
                "`{token}`: a `*` pattern is only valid after `1 of` or `all of`"
            ));
        }
        self.reference(token).map(Expr::Block)
    }

    /// `1 of X*`, `all of X*`, `1 of them`, `all of them`, after the quantifier token.
    fn parse_quantifier(&mut self, quantifier: &str) -> Result<Expr, String> {
        let all = if quantifier.eq_ignore_ascii_case("all") {
            true
        } else if quantifier == "1" {
            false
        } else if quantifier.eq_ignore_ascii_case("any") {
            return Err("`any of` is not supported (write `1 of`)".to_string());
        } else {
            return Err(format!(
                "`{quantifier} of` is not supported (only `1 of` and `all of`)"
            ));
        };
        self.at += 1; // `of`
        let Some(target) = self.next() else {
            return Err(format!("`{quantifier} of` has nothing after it"));
        };
        let matched: Vec<&'a str> = if target.eq_ignore_ascii_case("them") {
            self.available.to_vec()
        } else if let Some(prefix) = target.strip_suffix('*') {
            if prefix.contains('*') {
                return Err(format!(
                    "`{target}`: a pattern may only have one `*`, at its end"
                ));
            }
            self.available
                .iter()
                .copied()
                .filter(|name| name.starts_with(prefix))
                .collect()
        } else if target.contains('*') {
            return Err(format!(
                "`{target}`: a pattern may only have one `*`, at its end"
            ));
        } else if is_keyword(target) || target == "(" || target == ")" {
            return Err(format!(
                "`{quantifier} of {target}`: not a block name or pattern"
            ));
        } else {
            self.available
                .iter()
                .copied()
                .filter(|name| *name == target)
                .collect()
        };
        if matched.is_empty() {
            return Err(format!(
                "`{quantifier} of {target}` matches no block of this rule (an empty set would \
                 make the rule match vacuously or never)"
            ));
        }
        let indices: Vec<usize> = matched
            .into_iter()
            .map(|name| self.index_of(name))
            .collect();
        Ok(if all {
            Expr::AllOf(indices)
        } else {
            Expr::AnyOf(indices)
        })
    }

    /// A reference to one block by name: it must exist.
    fn reference(&mut self, name: &str) -> Result<usize, String> {
        match self.available.iter().find(|n| **n == name) {
            Some(found) => Ok(self.index_of(found)),
            None => Err(format!(
                "unknown block `{name}` (no such key in `detection`)"
            )),
        }
    }

    fn index_of(&mut self, name: &'a str) -> usize {
        if let Some(at) = self.referenced.iter().position(|n| *n == name) {
            return at;
        }
        self.referenced.push(name);
        self.referenced.len() - 1
    }
}

fn enter(depth: usize) -> Result<usize, String> {
    if depth >= MAX_DEPTH {
        return Err(format!(
            "parentheses and `not` nest more than {MAX_DEPTH} deep"
        ));
    }
    Ok(depth + 1)
}
