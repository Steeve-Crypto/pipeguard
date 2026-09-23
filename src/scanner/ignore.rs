use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct IgnoreSet {
    pub rules: Vec<String>,
    pub path_prefixes: Vec<String>,
}

impl IgnoreSet {
    pub fn ignores_rule(&self, rule_id: &str) -> bool {
        self.rules.iter().any(|r| r == rule_id)
    }

    pub fn ignores_path(&self, path: &Path) -> bool {
        let rendered = path.to_string_lossy().replace('\\', "/");
        self.path_prefixes.iter().any(|p| {
            let needle = p.trim_end_matches('/').trim_end_matches('*');
            rendered.contains(needle)
        })
    }
}

/// Walk up from `start` and load the nearest `.pipeguardignore`.
pub fn load(start: &Path) -> IgnoreSet {
    let mut dir = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };

    for _ in 0..8 {
        let candidate = dir.join(".pipeguardignore");
        if candidate.is_file() {
            return parse(&candidate);
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }
    IgnoreSet::default()
}

fn parse(path: &PathBuf) -> IgnoreSet {
    let Ok(text) = fs::read_to_string(path) else {
        return IgnoreSet::default();
    };
    parse_text(&text)
}

pub fn parse_text(text: &str) -> IgnoreSet {
    let mut set = IgnoreSet::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains('/') || line.contains('*') || line.contains('.') {
            set.path_prefixes.push(line.to_string());
        } else {
            set.rules.push(line.to_string());
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_rules_and_paths() {
        let set = parse_text("# comment\nself-hosted-runner\nexamples/\n*.lock\n");
        assert!(set.ignores_rule("self-hosted-runner"));
        assert!(!set.ignores_rule("unpinned-action"));
        assert!(set.ignores_path(Path::new("repo/examples/bad-workflow.yml")));
    }

    #[test]
    fn empty_text_is_noop() {
        let set = parse_text("");
        assert!(set.rules.is_empty());
        assert!(set.path_prefixes.is_empty());
    }
}
