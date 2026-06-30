//! Self-contained, deterministic server-side syntax highlighting.
//!
//! A tiny single-pass lexer wraps recognized tokens (comments, strings, numbers, keywords) in
//! `<span class="tok-*">` elements; the CSS for those classes lives in `static/app.css`. There
//! is NO external dependency (no syntect, no LLM): the highlighter is a few hundred lines of
//! pure Rust driven by a per-language [`Syntax`] descriptor.
//!
//! Safety / backward-compatibility contract:
//! - Every emitted character is HTML-escaped exactly as [`crate::handlers::esc`] would, and the
//!   concatenation of all token texts equals the escaped source. So the rendered body is never
//!   less safe than the previous plain `esc(body)` path, and unrecognized/`plaintext` languages
//!   fall back to byte-identical `esc(body)` output.
//! - Languages without a [`Syntax`] (e.g. `plaintext`, `html`, `markdown`, `diff`) are escaped
//!   verbatim with NO span wrapping, so existing rendered output is unchanged for them.

use crate::handlers::esc;

/// Per-language lexer rules. A `None` lookup => plaintext fallback (`esc` only).
struct Syntax {
    /// Line-comment prefixes (e.g. `//`, `#`, `--`); the rest of the line is a comment.
    line_comments: &'static [&'static str],
    /// Optional `(open, close)` block-comment delimiters (e.g. `/* */`).
    block_comment: Option<(&'static str, &'static str)>,
    /// String delimiters (e.g. `"`, `'`, `` ` ``). Backslash escapes the next char.
    strings: &'static [char],
    /// Reserved words highlighted as keywords (whole-identifier match only).
    keywords: &'static [&'static str],
    /// Case-insensitive keyword match (SQL).
    keywords_ci: bool,
}

/// Highlight `source` for `language`, returning safe (already-escaped) HTML. Falls back to plain
/// escaping for unknown / plaintext languages, so the output is identical to the legacy path.
pub fn highlight(language: &str, source: &str) -> String {
    match syntax_for(language) {
        Some(syntax) => highlight_with(&syntax, source),
        None => esc(source),
    }
}

fn highlight_with(syntax: &Syntax, source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(source.len() + source.len() / 4 + 16);
    let mut i = 0;
    while i < n {
        // 1) line comment
        if let Some(end) = match_line_comment(syntax, &chars, i) {
            push_span(&mut out, "tok-com", &chars[i..end]);
            i = end;
            continue;
        }
        // 2) block comment
        if let Some(end) = match_block_comment(syntax, &chars, i) {
            push_span(&mut out, "tok-com", &chars[i..end]);
            i = end;
            continue;
        }
        // 3) string literal
        if syntax.strings.contains(&chars[i]) {
            let end = scan_string(&chars, i);
            push_span(&mut out, "tok-str", &chars[i..end]);
            i = end;
            continue;
        }
        // 4) number (only when not in the middle of an identifier)
        if chars[i].is_ascii_digit() && !is_ident_char(prev_char(&chars, i)) {
            let end = scan_number(&chars, i);
            push_span(&mut out, "tok-num", &chars[i..end]);
            i = end;
            continue;
        }
        // 5) identifier / keyword
        if is_ident_start(chars[i]) {
            let end = scan_ident(&chars, i);
            let word: String = chars[i..end].iter().collect();
            if is_keyword(syntax, &word) {
                push_span(&mut out, "tok-kw", &chars[i..end]);
            } else {
                push_escaped(&mut out, &chars[i..end]);
            }
            i = end;
            continue;
        }
        // 6) default: a single escaped character (preserves contiguity of escaped runs)
        push_escaped(&mut out, &chars[i..i + 1]);
        i += 1;
    }
    out
}

fn match_line_comment(syntax: &Syntax, chars: &[char], i: usize) -> Option<usize> {
    for prefix in syntax.line_comments {
        if starts_with(chars, i, prefix) {
            let mut j = i;
            while j < chars.len() && chars[j] != '\n' {
                j += 1;
            }
            return Some(j);
        }
    }
    None
}

fn match_block_comment(syntax: &Syntax, chars: &[char], i: usize) -> Option<usize> {
    let (open, close) = syntax.block_comment?;
    if !starts_with(chars, i, open) {
        return None;
    }
    let close_chars: Vec<char> = close.chars().collect();
    let mut j = i + open.chars().count();
    while j < chars.len() {
        if starts_with(chars, j, close) {
            return Some(j + close_chars.len());
        }
        j += 1;
    }
    Some(chars.len()) // unterminated block comment runs to EOF
}

/// Scan a string starting at the opening delimiter `chars[i]`. Honors `\` escapes; stops at the
/// closing delimiter, a newline, or EOF (so an unterminated string never eats the whole file).
fn scan_string(chars: &[char], i: usize) -> usize {
    let delim = chars[i];
    let mut j = i + 1;
    while j < chars.len() {
        match chars[j] {
            '\\' => j += 2, // skip the escaped char
            '\n' => return j,
            c if c == delim => return j + 1,
            _ => j += 1,
        }
    }
    chars.len()
}

fn scan_number(chars: &[char], i: usize) -> usize {
    let mut j = i;
    while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '.' || chars[j] == '_')
    {
        j += 1;
    }
    j
}

fn scan_ident(chars: &[char], i: usize) -> usize {
    let mut j = i;
    while j < chars.len() && is_ident_char(Some(chars[j])) {
        j += 1;
    }
    j
}

fn is_keyword(syntax: &Syntax, word: &str) -> bool {
    if syntax.keywords_ci {
        let lower = word.to_ascii_lowercase();
        syntax.keywords.iter().any(|k| k.eq_ignore_ascii_case(&lower))
    } else {
        syntax.keywords.contains(&word)
    }
}

fn starts_with(chars: &[char], i: usize, needle: &str) -> bool {
    let mut k = i;
    for nc in needle.chars() {
        if k >= chars.len() || chars[k] != nc {
            return false;
        }
        k += 1;
    }
    true
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: Option<char>) -> bool {
    matches!(c, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_')
}

fn prev_char(chars: &[char], i: usize) -> Option<char> {
    if i == 0 {
        None
    } else {
        Some(chars[i - 1])
    }
}

/// Append the escaped text of `seg` wrapped in `<span class="{class}">…</span>`.
fn push_span(out: &mut String, class: &str, seg: &[char]) {
    out.push_str("<span class=\"");
    out.push_str(class);
    out.push_str("\">");
    push_escaped(out, seg);
    out.push_str("</span>");
}

/// Append the HTML-escaped text of `seg` (identical char-for-char to [`esc`]).
fn push_escaped(out: &mut String, seg: &[char]) {
    for &c in seg {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-language syntax table (trusted allow-list; mirrors handlers::LANGUAGES).
// ---------------------------------------------------------------------------

const KW_RUST: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
    "use", "where", "while", "box",
];

const KW_PYTHON: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
    "None", "nonlocal", "not", "or", "pass", "raise", "return", "True", "False", "try", "while",
    "with", "yield",
];

const KW_JS: &[&str] = &[
    "async", "await", "break", "case", "catch", "class", "const", "continue", "default", "delete",
    "do", "else", "export", "extends", "finally", "for", "from", "function", "if", "import", "in",
    "instanceof", "let", "new", "null", "of", "return", "super", "switch", "this", "throw", "try",
    "typeof", "undefined", "var", "void", "while", "yield", "true", "false", "interface", "type",
    "enum", "implements", "public", "private", "protected", "readonly", "as",
];

const KW_GO: &[&str] = &[
    "break", "case", "chan", "const", "continue", "default", "defer", "else", "fallthrough", "for",
    "func", "go", "goto", "if", "import", "interface", "map", "package", "range", "return", "select",
    "struct", "switch", "type", "var", "nil", "true", "false",
];

const KW_C_LIKE: &[&str] = &[
    "auto", "break", "case", "catch", "char", "class", "const", "continue", "default", "delete",
    "do", "double", "else", "enum", "extends", "extern", "final", "finally", "float", "for", "goto",
    "if", "implements", "import", "int", "interface", "long", "namespace", "new", "null", "package",
    "private", "protected", "public", "return", "short", "signed", "sizeof", "static", "struct",
    "switch", "template", "this", "throw", "throws", "try", "typedef", "union", "unsigned", "using",
    "virtual", "void", "volatile", "while", "true", "false", "fun", "val", "var", "let", "func",
];

const KW_SHELL: &[&str] = &[
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "function", "in", "select", "return", "export", "local", "readonly", "declare", "set", "unset",
    "echo", "exit",
];

const KW_SQL: &[&str] = &[
    "select", "from", "where", "insert", "into", "values", "update", "set", "delete", "create",
    "table", "index", "view", "drop", "alter", "add", "column", "primary", "key", "foreign",
    "references", "unique", "not", "null", "default", "and", "or", "join", "inner", "left", "right",
    "outer", "on", "group", "by", "order", "having", "limit", "offset", "distinct", "as", "in",
    "exists", "between", "like", "case", "when", "then", "end", "with", "conflict", "do", "nothing",
];

const KW_JSON: &[&str] = &["true", "false", "null"];

/// Look up the lexer rules for a stored language token. `None` => plaintext fallback.
fn syntax_for(language: &str) -> Option<Syntax> {
    let c_line: &[&str] = &["//"];
    let hash_line: &[&str] = &["#"];
    let dash_line: &[&str] = &["--"];
    let cblock = Some(("/*", "*/"));
    let dq_sq: &[char] = &['"', '\''];
    let dq_sq_bt: &[char] = &['"', '\'', '`'];
    let dq: &[char] = &['"'];
    let sq: &[char] = &['\''];

    let s = match language {
        "rust" => Syntax {
            line_comments: c_line,
            block_comment: cblock,
            strings: dq,
            keywords: KW_RUST,
            keywords_ci: false,
        },
        "python" | "ruby" => Syntax {
            line_comments: hash_line,
            block_comment: None,
            strings: dq_sq,
            keywords: KW_PYTHON,
            keywords_ci: false,
        },
        "javascript" | "typescript" => Syntax {
            line_comments: c_line,
            block_comment: cblock,
            strings: dq_sq_bt,
            keywords: KW_JS,
            keywords_ci: false,
        },
        "go" => Syntax {
            line_comments: c_line,
            block_comment: cblock,
            strings: dq_sq_bt,
            keywords: KW_GO,
            keywords_ci: false,
        },
        "c" | "cpp" | "csharp" | "java" | "kotlin" | "swift" | "php" => Syntax {
            line_comments: c_line,
            block_comment: cblock,
            strings: dq_sq,
            keywords: KW_C_LIKE,
            keywords_ci: false,
        },
        "bash" | "dockerfile" => Syntax {
            line_comments: hash_line,
            block_comment: None,
            strings: dq_sq,
            keywords: KW_SHELL,
            keywords_ci: false,
        },
        "sql" => Syntax {
            line_comments: dash_line,
            block_comment: cblock,
            strings: sq,
            keywords: KW_SQL,
            keywords_ci: true,
        },
        "json" => Syntax {
            line_comments: &[],
            block_comment: None,
            strings: dq,
            keywords: KW_JSON,
            keywords_ci: false,
        },
        "css" => Syntax {
            line_comments: &[],
            block_comment: cblock,
            strings: dq_sq,
            keywords: &[],
            keywords_ci: false,
        },
        "yaml" | "toml" | "ini" => Syntax {
            line_comments: hash_line,
            block_comment: None,
            strings: dq_sq,
            keywords: &[],
            keywords_ci: false,
        },
        // plaintext, html, xml, markdown, diff and anything unknown -> escape only.
        _ => return None,
    };
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::esc;

    #[test]
    fn plaintext_is_byte_identical_to_esc() {
        let src = "<script>alert('x')</script>\nplain & simple";
        assert_eq!(highlight("plaintext", src), esc(src));
        assert_eq!(highlight("unknown-lang", src), esc(src));
        assert_eq!(highlight("html", src), esc(src));
    }

    #[test]
    fn concatenated_token_text_equals_escaped_source() {
        // Stripping all <span> tags must recover exactly esc(source) for every language.
        let src = "fn main() { let x = 42; /* c */ let s = \"hi\"; } // tail";
        let html = highlight("rust", src);
        let stripped = strip_spans(&html);
        assert_eq!(stripped, esc(src));
    }

    #[test]
    fn rust_keyword_and_string_get_spans() {
        let html = highlight("rust", "fn x() { let s = \"hi\"; }");
        assert!(html.contains("<span class=\"tok-kw\">fn</span>"));
        assert!(html.contains("<span class=\"tok-kw\">let</span>"));
        assert!(html.contains("<span class=\"tok-str\">&quot;hi&quot;</span>"));
    }

    #[test]
    fn html_escape_stays_contiguous_for_non_syntax_langs() {
        // The xss flow test depends on `&lt;script&gt;` staying contiguous for html.
        let html = highlight("html", "<script>alert('xss')</script>");
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn sql_keywords_are_case_insensitive() {
        let html = highlight("sql", "SELECT * from T");
        assert!(html.contains("<span class=\"tok-kw\">SELECT</span>"));
        assert!(html.contains("<span class=\"tok-kw\">from</span>"));
    }

    #[test]
    fn unterminated_string_does_not_panic() {
        let _ = highlight("rust", "let s = \"oops");
        let _ = highlight("rust", "/* never closed");
    }

    /// Remove every `<span ...>` and `</span>` tag (test helper only).
    fn strip_spans(html: &str) -> String {
        let mut out = String::new();
        let bytes = html.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'<' {
                // a span open/close tag — skip to the next '>'
                if html[i..].starts_with("<span") || html[i..].starts_with("</span>") {
                    while i < bytes.len() && bytes[i] != b'>' {
                        i += 1;
                    }
                    i += 1; // skip '>'
                    continue;
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }
}
