use anyhow::{bail, Context};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BlockStrategy {
    BlockFiles,
    BlockNetwork,
    BlockBoth,
}

impl Default for BlockStrategy {
    fn default() -> Self {
        BlockStrategy::BlockFiles
    }
}

impl std::fmt::Display for BlockStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockStrategy::BlockFiles => write!(f, "block_files"),
            BlockStrategy::BlockNetwork => write!(f, "block_network"),
            BlockStrategy::BlockBoth => write!(f, "block_both"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub patterns: Vec<String>,
    pub threshold: u32,
    #[serde(default)]
    pub target_pid: u32,
    #[serde(default)]
    pub strategy: BlockStrategy,
}

pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file: {}", path.display()))?;

    let config: Config =
        serde_json::from_str(&data).context("parsing config file")?;

    if config.patterns.is_empty() {
        bail!("config file must contain at least one pattern");
    }
    if config.threshold == 0 {
        bail!("threshold must be greater than 0");
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_config(json: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", json).unwrap();
        f
    }

    #[test]
    fn test_load_valid_config() {
        let f = write_config(
            r#"{"patterns":["/etc/passwd"],"threshold":2}"#,
        );
        let cfg = load_config(f.path()).unwrap();
        assert_eq!(cfg.patterns, vec!["/etc/passwd"]);
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.target_pid, 0);
        assert_eq!(cfg.strategy, BlockStrategy::BlockFiles);
    }

    #[test]
    fn test_load_config_with_strategy() {
        let f = write_config(
            r#"{"patterns":["*.log"],"threshold":1,"strategy":"block_network"}"#,
        );
        let cfg = load_config(f.path()).unwrap();
        assert_eq!(cfg.strategy, BlockStrategy::BlockNetwork);
    }

    #[test]
    fn test_load_config_missing_patterns() {
        let f = write_config(r#"{"patterns":[],"threshold":1}"#);
        assert!(load_config(f.path()).is_err());
    }

    #[test]
    fn test_load_config_zero_threshold() {
        let f = write_config(r#"{"patterns":["/etc/passwd"],"threshold":0}"#);
        assert!(load_config(f.path()).is_err());
    }
}
