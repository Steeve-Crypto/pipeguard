use colored::*;
use serde::Serialize;
use serde_json::json;

use crate::scanner::Finding;
use crate::Severity;

#[derive(Serialize)]
struct JsonFinding {
    file: String,
    rule_id: String,
    title: String,
    description: String,
    severity: String,
    line: Option<usize>,
    snippet: Option<String>,
}

pub fn print_findings(
    findings: &[Finding],
    as_json: bool,
    as_sarif: bool,
    quiet: bool,
    min_severity: Severity,
    exclude: &[String],
) -> usize {
    let filtered: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .filter(|f| !exclude.iter().any(|id| id == &f.rule_id))
        .collect();

    if as_sarif {
        print_sarif(&filtered);
        return filtered.len();
    }

    if as_json {
        let json_findings: Vec<JsonFinding> = filtered
            .iter()
            .map(|f| JsonFinding {
                file: f.file.display().to_string(),
                rule_id: f.rule_id.clone(),
                title: f.title.clone(),
                description: f.description.clone(),
                severity: format!("{:?}", f.severity).to_lowercase(),
                line: f.line,
                snippet: f.snippet.clone(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_findings).unwrap());
        return filtered.len();
    }

    if quiet {
        println!("{}", filtered.len());
        return filtered.len();
    }

    if filtered.is_empty() {
        println!(
            "{}",
            "✓ No issues found (above the minimum severity)"
                .green()
                .bold()
        );
        return 0;
    }

    let critical = filtered.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = filtered.iter().filter(|f| f.severity == Severity::High).count();
    let medium = filtered.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = filtered.iter().filter(|f| f.severity == Severity::Low).count();

    println!(
        "\n{} {} finding(s)  critical={} high={} medium={} low={}\n",
        "⚠".yellow().bold(),
        filtered.len().to_string().bold(),
        critical,
        high,
        medium,
        low
    );

    for f in &filtered {
        let sev_str = match f.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".blue(),
        };

        println!("{} [{}] {}", sev_str, f.rule_id.cyan(), f.title.bold());
        println!("   File : {}", f.file.display());
        if let Some(line) = f.line {
            println!("   Line : {}", line);
        }
        if let Some(ref snip) = f.snippet {
            println!("   Code : {}", snip.dimmed());
        }
        println!("   {}", f.description);
        println!();
    }

    filtered.len()
}

fn severity_to_sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn print_sarif(findings: &[&Finding]) {
    let mut results = Vec::new();
    let mut rules_map = std::collections::HashMap::new();

    for f in findings {
        rules_map.entry(f.rule_id.clone()).or_insert_with(|| {
            json!({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&f.severity)
                }
            })
        });

        let mut result = json!({
            "ruleId": f.rule_id,
            "level": severity_to_sarif_level(&f.severity),
            "message": { "text": f.description },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file.display().to_string()
                    }
                }
            }]
        });

        if let Some(line) = f.line {
            result["locations"][0]["physicalLocation"]["region"] = json!({
                "startLine": line
            });
        }

        results.push(result);
    }

    let rules: Vec<_> = rules_map.into_values().collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pipeguard",
                    "informationUri": "https://github.com/Steeve-Crypto/pipeguard",
                    "version": "0.1.5",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
}
