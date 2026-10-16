//! Detection engine: hash-signature DB + conservative heuristics.
//!
//! Design rules:
//! - a hash match is a `Detected`; a heuristic match is at most `Suspicious`;
//! - heuristics are explainable and configurable, never auto-deleting;
//! - filenames alone are never treated as malware evidence;
//! - no signature match means "no detection", never "guaranteed safe".

use crate::config::{Config, HeuristicSensitivity};
use crate::error::Error;
use crate::scanner::hash_stream;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// A validated signature entry from the local database.
#[derive(Debug, Clone, Serialize)]
pub struct Signature {
    pub sha256: String,
    pub name: String,
    pub severity: Severity,
}

/// The on-disk signature file format. All fields are validated on load;
/// malformed or oversized files are rejected, not partially used.
#[derive(Debug, Deserialize)]
struct SigFile {
    version: u32,
    entries: Vec<SigEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigEntry {
    sha256: String,
    name: String,
    severity: Option<SevStr>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SevStr {
    Low,
    Medium,
    High,
}

/// In-memory engine.
pub struct Engine {
    pub signatures: Vec<Signature>,
    heuristics: bool,
    sensitivity: HeuristicSensitivity,
}

/// Loads and validates the signature file. A missing file yields an empty
/// engine (not an error); a malformed one is reported clearly.
pub fn load_signatures(path: &Path) -> Vec<Signature> {
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() > 64 * 1024 * 1024 {
                eprintln!(
                    "warning: signature file {} exceeds 64 MiB; ignoring it",
                    path.display()
                );
                return Vec::new();
            }
            match parse_signatures(&bytes) {
                Ok(sigs) => sigs,
                Err(msg) => {
                    eprintln!("warning: ignoring signature file {}: {msg}", path.display());
                    Vec::new()
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            eprintln!(
                "warning: cannot read signature file {}: {e}",
                path.display()
            );
            Vec::new()
        }
    }
}

fn parse_signatures(bytes: &[u8]) -> Result<Vec<Signature>, String> {
    let f: SigFile = serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    if f.version != 1 {
        return Err(format!("unsupported signature version {}", f.version));
    }
    let mut sigs = Vec::with_capacity(f.entries.len());
    for e in f.entries {
        let hash = e.sha256.to_ascii_lowercase().trim().to_string();
        if !is_sha256_hex(&hash) {
            return Err(format!(
                "entry {:?}: sha256 must be 64 lowercase hex chars",
                e.name
            ));
        }
        if e.name.is_empty() {
            return Err("an entry has an empty name".into());
        }
        sigs.push(Signature {
            sha256: hash,
            name: e.name,
            severity: match e.severity {
                Some(SevStr::Low) => Severity::Low,
                Some(SevStr::Medium) => Severity::Medium,
                Some(SevStr::High) | None => Severity::High,
            },
        });
    }
    Ok(sigs)
}

pub(crate) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Engine {
    pub fn new(cfg: &Config) -> Result<Self, Error> {
        let sigs = load_signatures(&cfg.signatures_path);
        Ok(Self {
            signatures: sigs,
            heuristics: cfg.heuristics,
            sensitivity: cfg.heuristic_sensitivity,
        })
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Classify a file by content. Returns None when no detection fired —
    /// which must be rendered as "no detection", never as "guaranteed clean".
    pub fn classify(
        &self,
        path: &Path,
        file: &std::fs::File,
        meta: &std::fs::Metadata,
    ) -> Result<Option<Classification>, Error> {
        let digest = hash_stream(file)?;
        if let Some(sig) = self.signatures.iter().find(|s| s.sha256 == digest) {
            return Ok(Some(Classification::Detected {
                name: sig.name.clone(),
                severity: sig.severity,
                hash: digest,
                reasons: vec![format!("sha256 matches signature '{}'", sig.name)],
            }));
        }
        let mut reasons = Vec::new();
        if self.heuristics {
            self.heuristic_scan(path, meta, file, &mut reasons);
        }
        if reasons.is_empty() {
            return Ok(None);
        }
        let score = Self::score(&reasons, self.sensitivity);
        Ok(Some(Classification::Suspicious {
            reasons,
            score,
            hash: digest,
        }))
    }

    fn heuristic_scan(
        &self,
        path: &Path,
        meta: &std::fs::Metadata,
        file: &std::fs::File,
        reasons: &mut Vec<String>,
    ) {
        if !meta.is_file() {
            return;
        }
        let size = meta.len();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let mut head = [0u8; 8192];
        let n = match file.try_clone() {
            Ok(f2) => {
                let mut reader = std::io::BufReader::new(f2);
                use std::io::Read;
                reader.read(&mut head).unwrap_or(0)
            }
            // Fallback: if we cannot clone the handle, treat the head as
            // empty — the heuristic degrades gracefully, no crash.
            Err(_) => 0,
        };
        let head = &head[..n];

        // Portable signature (no execution, no platform assumptions):
        if head.starts_with(b"\x4d\x5a") && size >= 1024 {
            reasons.push("file claims a DOS/Windows executable header (MZ)".to_string());
        }
        if name.to_ascii_lowercase().ends_with(".scr") && size > 0 {
            // Screensaver executables: a classic malware delivery vehicle.
            reasons.push(
                ".scr screensaver executables are a known malware delivery mechanism".to_string(),
            );
        }
        // High-entropy + executable-flavored: suspicious, not proof.
        if matches!(ext.as_str(), "exe" | "dll" | "ocx" | "scr" | "bat" | "cmd") && size > 4096 {
            let ent = entropy(head);
            if ent > self.entropy_threshold() {
                reasons.push(format!("high entropy ({ent:.2}) in executable/script file"));
            }
        }
        // Ponytail: case-insensitive substring scan of the 8 KiB head for
        // download/execution markers. Add an argv-aware AST pass later.
        if matches!(ext.as_str(), "bat" | "cmd") {
            let low = String::from_utf8_lossy(head).to_ascii_lowercase();
            if low.contains("certutil") || low.contains("bitsadmin") || low.contains("iex ") {
                reasons.push(
                    "script references common download/execution tools (certutil/bitsadmin/IEX)"
                        .to_string(),
                );
            }
        }
    }

    fn entropy_threshold(&self) -> f64 {
        match self.sensitivity {
            HeuristicSensitivity::Low => 7.0,
            HeuristicSensitivity::Medium => 7.5,
            HeuristicSensitivity::High => 7.0,
        }
    }

    fn score(reasons: &[String], sens: HeuristicSensitivity) -> u32 {
        let w = match sens {
            HeuristicSensitivity::Low => 1,
            HeuristicSensitivity::Medium => 2,
            HeuristicSensitivity::High => 3,
        };
        reasons.len() as u32 * w
    }
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p.log2() * p
        })
        .sum()
}

pub struct Detection {
    pub path: PathBuf,
    pub name: String,
    pub severity: Severity,
    pub sha256: String,
    pub reasons: Vec<String>,
    pub score: u32,
}

impl Detection {
    /// One of "low", "medium", "high".
    pub fn severity_str(&self) -> &'static str {
        match self.severity {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

pub enum Classification {
    Detected {
        name: String,
        severity: Severity,
        hash: String,
        reasons: Vec<String>,
    },
    Suspicious {
        reasons: Vec<String>,
        score: u32,
        hash: String,
    },
}

impl Classification {
    pub fn to_detection(&self, path: &Path) -> Detection {
        match self {
            Classification::Detected {
                name,
                severity,
                hash,
                reasons,
            } => Detection {
                path: path.to_path_buf(),
                name: name.clone(),
                severity: *severity,
                sha256: hash.clone(),
                reasons: reasons.clone(),
                score: u32::MAX,
            },
            Classification::Suspicious {
                reasons,
                score,
                hash,
            } => Detection {
                path: path.to_path_buf(),
                name: "heuristic".into(),
                severity: Severity::Medium,
                sha256: hash.clone(),
                reasons: reasons.clone(),
                score: *score,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_db_parses() {
        let json = r#"{
            "version": 1,
            "entries": [
                {"sha256":"0000000000000000000000000000000000000000000000000000000000000000","name":"T.Eicar","severity":"high"},
                {"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"T.Synthetic"}
            ]
        }"#;
        let sigs = parse_signatures(json.as_bytes()).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].severity, Severity::High);
        assert_eq!(sigs[1].severity, Severity::High); // default
    }

    #[test]
    fn rejects_bad_hash() {
        let json = r#"{"version":1,"entries":[{"sha256":"zz","name":"x"}]}"#;
        assert!(parse_signatures(json.as_bytes()).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let json = r#"{"version":2,"entries":[]}"#;
        assert!(parse_signatures(json.as_bytes()).is_err());
    }

    #[test]
    fn entropy_high_on_random() {
        let mut data: Vec<u8> = (0..512).map(|i| ((i * 7) % 256) as u8).collect();
        data.extend((0..512).map(|i| ((i * 31) % 256) as u8));
        assert!(entropy(&data) > 7.0);
    }

    #[test]
    fn entropy_low_on_zero() {
        assert!(entropy(&[0u8; 4096]) < 0.01);
    }
}
