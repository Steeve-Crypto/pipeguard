use anyhow::Result;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::Severity;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub min_severity: Option<String>,
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Config {
    pub fn min_severity(&self) -> Option<Severity> {
        self.min_severity.as_deref().and_then(parse_severity)
    }

    pub fn fail_on(&self) -> Option<Severity> {
        self.fail_on.as_deref().and_then(parse_severity)
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Walk up from `start` looking for pipeguard.toml (max 6 levels).
pub fn load(start: &Path) -> Result<Config> {
    let mut dir = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };

    for _ in 0..6 {
        let candidate = dir.join("pipeguard.toml");
        if candidate.is_file() {
            return parse_file(&candidate);
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }
    Ok(Config::default())
}

fn parse_file(path: &PathBuf) -> Result<Config> {
    let text = fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&text)?;
    Ok(cfg)
}
