use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

use crate::Format;

pub fn run(input: &Path, to: Format, output: Option<&Path>) -> Result<()> {
    let content = fs::read_to_string(input)
        .with_context(|| format!("failed to read input file: {}", input.display()))?;

    let value = parse_any(&content, input)?;

    let converted = match to {
        Format::Json => serde_json::to_string_pretty(&value)?,
        Format::Yaml => serde_yaml::to_string(&value)?,
        Format::Toml => {
            // toml crate works best with tables; we serialize the Value
            let toml_value: toml::Value = serde_json::from_value(
                serde_json::to_value(&value).context("intermediate JSON conversion failed")?,
            )
            .context("failed to convert to TOML value")?;
            toml::to_string_pretty(&toml_value)?
        }
    };

    if let Some(out_path) = output {
        fs::write(out_path, &converted)
            .with_context(|| format!("failed to write output: {}", out_path.display()))?;
        eprintln!("Wrote {} → {}", input.display(), out_path.display());
    } else {
        print!("{}", converted);
    }

    Ok(())
}

fn parse_any(content: &str, path: &Path) -> Result<serde_yaml::Value> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "json" => {
            let v: serde_json::Value = serde_json::from_str(content)?;
            // Convert JSON → YAML Value for uniform handling
            let yaml_str = serde_json::to_string(&v)?;
            Ok(serde_yaml::from_str(&yaml_str)?)
        }
        "yml" | "yaml" => Ok(serde_yaml::from_str(content)?),
        "toml" => {
            let v: toml::Value = content.parse()?;
            let json = serde_json::to_value(v)?;
            let yaml_str = serde_json::to_string(&json)?;
            Ok(serde_yaml::from_str(&yaml_str)?)
        }
        _ => {
            // Try to detect
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
                let yaml_str = serde_json::to_string(&v)?;
                return Ok(serde_yaml::from_str(&yaml_str)?);
            }
            if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(content) {
                return Ok(v);
            }
            if let Ok(v) = content.parse::<toml::Value>() {
                let json = serde_json::to_value(v)?;
                let yaml_str = serde_json::to_string(&json)?;
                return Ok(serde_yaml::from_str(&yaml_str)?);
            }
            bail!("could not detect format of {}", path.display());
        }
    }
}
