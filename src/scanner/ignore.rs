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
