//! Configuration: safe defaults, overridable via `opensentinel.toml` in the
//! current directory or in the user config dir. Parsing errors are surfaced,
//! never silently downgraded.

use crate::error::{Error, ErrorKind};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeuristicSensitivity {
    Low,
    #[default]
    Medium,
    High,
}

impl HeuristicSensitivity {
    pub fn parse(s: &str) -> Result<Self, (Self, String)> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err((
                Self::Medium,
                format!("unknown heuristic sensitivity {s:?} (expected low|medium|high)"),
            )),
        }
    }
}

/// All user-tunable settings. Values outside the allowed range are rejected.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub concurrency: usize,
    pub max_file_size: u64,
    pub excluded: Vec<PathBuf>,
    pub heuristics: bool,
    pub heuristic_sensitivity: HeuristicSensitivity,
    pub signatures_path: PathBuf,
    pub quarantine_dir: PathBuf,
    pub quiet: bool,
    pub json: bool,
}

impl Config {
    /// Returns a config with safe defaults plus any `opensentinel.toml` found
    /// (current dir, then config dir). Absence of the file is not an error.
    pub fn load_default() -> Result<Self, Error> {
        let mut c = Self::defaults();
        if let Some(p) = Self::find_config_file() {
            let text = std::fs::read_to_string(&p).map_err(|e| {
                Error::new(ErrorKind::Config, format!("cannot read config {p:?}: {e}"))
            })?;
            c.apply_toml(&text)
                .map_err(|msg| Error::new(ErrorKind::Config, format!("config {p:?}: {msg}")))?;
        }
        Ok(c)
    }

    /// Safe defaults with no configuration file applied.
    pub fn defaults() -> Self {
        Self {
            concurrency: 4,
            max_file_size: 2u64 << 30, // 2 GiB default cap
            excluded: Vec::new(),
            heuristics: true,
            heuristic_sensitivity: HeuristicSensitivity::Medium,
            signatures_path: PathBuf::from("signatures.json"),
            quarantine_dir: PathBuf::from(".opensentinel-quarantine"),
            quiet: false,
            json: false,
        }
    }

    fn find_config_file() -> Option<PathBuf> {
        [
            PathBuf::from("opensentinel.toml"),
            config_dir()
                .map(|d| d.join("opensentinel.toml"))
                .unwrap_or_default(),
        ]
        .into_iter()
        .find(|cand| !cand.as_os_str().is_empty() && cand.is_file())
    }

    /// Render this config as a minimal TOML document using the keys the
    /// config file parser understands. The GUI settings screen uses this to
    /// persist changes without introducing a second config format.
    pub fn to_toml(&self) -> String {
        let sens = match self.heuristic_sensitivity {
            HeuristicSensitivity::Low => "low",
            HeuristicSensitivity::Medium => "medium",
            HeuristicSensitivity::High => "high",
        };
        let excluded: Vec<String> = self
            .excluded
            .iter()
            .map(|p| format!("\"{}\"", p.to_string_lossy()))
            .collect();
        format!(
            "concurrency = {}\n\
             max_file_size = {}\n\
             excluded = [{}]\n\
             heuristics = {}\n\
             heuristic_sensitivity = \"{sens}\"\n\
             signatures_path = \"{}\"\n\
             quarantine_dir = \"{}\"\n",
            self.concurrency,
            self.max_file_size,
            excluded.join(", "),
            self.heuristics,
            self.signatures_path.to_string_lossy(),
            self.quarantine_dir.to_string_lossy(),
        )
    }

    pub fn apply_toml(&mut self, text: &str) -> std::result::Result<(), String> {
        // Tiny TOML-subset parser: `key = value` lines, comments, no sections.
        for (i, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: missing '='", i + 1))?;
            let k = k.trim();
            let v = unquote(v.trim());
            match k {
                "concurrency" => {
                    let n: usize = v
                        .parse()
                        .map_err(|_| format!("line {}: concurrency must be an integer", i + 1))?;
                    if !(1..=64).contains(&n) {
                        return Err(format!("line {}: concurrency must be 1..=64", i + 1));
                    }
                    self.concurrency = n;
                }
                "max_file_size" => {
                    let n: u64 = v
                        .parse()
                        .map_err(|_| format!("line {}: max_file_size must be an integer", i + 1))?;
                    self.max_file_size = n;
                }
                "excluded" => {
                    let list = v
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .split(',')
                        .map(|s| unquote(s.trim()))
                        .filter(|s| !s.is_empty())
                        .map(PathBuf::from)
                        .collect();
                    self.excluded = list;
                }
                "heuristics" => {
                    self.heuristics = match v.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(format!("line {}: heuristics must be true|false", i + 1)),
                    };
                }
                "heuristic_sensitivity" => match HeuristicSensitivity::parse(&v) {
                    Ok(s) => self.heuristic_sensitivity = s,
                    Err((_, msg)) => return Err(format!("line {}: {msg}", i + 1)),
                },
                "signatures_path" => self.signatures_path = PathBuf::from(v),
                "quarantine_dir" => self.quarantine_dir = PathBuf::from(v),
                "quiet" => {
                    self.quiet = match v.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(format!("line {}: quiet must be true|false", i + 1)),
                    };
                }
                "json" => {
                    self.json = match v.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(format!("line {}: json must be true|false", i + 1)),
                    };
                }
                other => return Err(format!("line {}: unknown setting {other:?}", i + 1)),
            }
        }
        Ok(())
    }
}

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn config_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let c = Config::defaults();
        assert!(c.concurrency >= 1 && c.concurrency <= 64);
        assert_eq!(c.max_file_size, 2 << 30);
    }

    #[test]
    fn toml_subset_parses() {
        let mut c = Config::defaults();
        c.apply_toml("concurrency = 8\nmax_file_size = 100\n")
            .unwrap();
        assert_eq!(c.concurrency, 8);
        assert_eq!(c.max_file_size, 100);
    }

    #[test]
    fn toml_rejects_bad_values() {
        let mut c = Config::defaults();
        assert!(c.apply_toml("concurrency = 0").is_err());
        assert!(c.apply_toml("concurrency = 999").is_err());
        assert!(c.apply_toml("bogus = 1").is_err());
    }

    #[test]
    fn sensitivity_parse() {
        assert!(HeuristicSensitivity::parse("high").is_ok());
        assert!(HeuristicSensitivity::parse("x").is_err());
    }

    #[test]
    fn toml_round_trips() {
        let mut c = Config::defaults();
        c.concurrency = 8;
        c.heuristics = false;
        let parsed: Config = {
            let mut p = Config::defaults();
            p.apply_toml(&c.to_toml()).unwrap();
            p
        };
        assert_eq!(parsed.concurrency, c.concurrency);
        assert_eq!(parsed.heuristics, c.heuristics);
        assert_eq!(parsed.heuristic_sensitivity, c.heuristic_sensitivity);
    }
}
