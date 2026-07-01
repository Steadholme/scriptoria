//! Minimal line-level diff (LCS-based) for the revision history view.
//!
//! `line_diff` compares two page bodies line-by-line and returns the edit script as a flat list
//! of [`DiffLine`]s (unchanged / removed / added), in reading order. It is pure and allocation-
//! bounded by the two inputs; the handler renders each line server-side (every line escaped). The
//! classic dynamic-programming LCS keeps the shared lines aligned so only the true changes show
//! as `+`/`-`.

/// What happened to one line going from the `old` body to the `new` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Present unchanged in both revisions (context).
    Equal,
    /// Present in `old`, gone in `new` (removed).
    Delete,
    /// New in `new`, absent from `old` (added).
    Insert,
}

/// One line of the rendered diff: its [`Op`] and the line text (without the trailing newline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub op: Op,
    pub text: String,
}

/// Line-level diff between `old` and `new` via a longest-common-subsequence table.
///
/// Lines are split on `\n` (a trailing newline does not create an empty final line). The result is
/// the minimal edit script in reading order: shared lines are `Equal`, lines only in `old` are
/// `Delete`, lines only in `new` are `Insert`. Two identical bodies yield all-`Equal`.
pub fn line_diff(old: &str, new: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let n = a.len();
    let m = b.len();

    // lcs[i][j] = length of the LCS of a[i..] and b[j..]. Filled bottom-up.
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    // Walk the table from the top-left, emitting the edit script.
    let mut out = Vec::with_capacity(n.max(m));
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push(DiffLine { op: Op::Equal, text: a[i].to_string() });
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(DiffLine { op: Op::Delete, text: a[i].to_string() });
            i += 1;
        } else {
            out.push(DiffLine { op: Op::Insert, text: b[j].to_string() });
            j += 1;
        }
    }
    while i < n {
        out.push(DiffLine { op: Op::Delete, text: a[i].to_string() });
        i += 1;
    }
    while j < m {
        out.push(DiffLine { op: Op::Insert, text: b[j].to_string() });
        j += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops(lines: &[DiffLine]) -> Vec<(Op, &str)> {
        lines.iter().map(|l| (l.op, l.text.as_str())).collect()
    }

    #[test]
    fn identical_bodies_are_all_equal() {
        let d = line_diff("a\nb\nc", "a\nb\nc");
        assert_eq!(ops(&d), vec![(Op::Equal, "a"), (Op::Equal, "b"), (Op::Equal, "c")]);
    }

    #[test]
    fn added_and_removed_lines_are_marked() {
        // "b" removed, "x" inserted; surrounding lines stay context.
        let d = line_diff("a\nb\nc", "a\nx\nc");
        assert_eq!(
            ops(&d),
            vec![(Op::Equal, "a"), (Op::Delete, "b"), (Op::Insert, "x"), (Op::Equal, "c")]
        );
    }

    #[test]
    fn pure_append_only_inserts() {
        let d = line_diff("a", "a\nb\nc");
        assert_eq!(ops(&d), vec![(Op::Equal, "a"), (Op::Insert, "b"), (Op::Insert, "c")]);
    }

    #[test]
    fn empty_old_inserts_everything() {
        let d = line_diff("", "one\ntwo");
        assert_eq!(ops(&d), vec![(Op::Insert, "one"), (Op::Insert, "two")]);
    }
}
