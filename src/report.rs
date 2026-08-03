use colored::*;
use serde::Serialize;

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

pub fn print_findings(findings: &[Finding], as_json: bool, min_severity: Severity) {
    let filtered: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .collect();

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
        return;
    }

    if filtered.is_empty() {
        println!("{}", "✓ No issues found (above the minimum severity)".green().bold());
        return;
    }

    println!(
        "\n{} {} finding(s) found\n",
        "⚠".yellow().bold(),
        filtered.len().to_string().bold()
    );

    for f in filtered {
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
}
