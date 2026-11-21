//! 設定檔：%APPDATA%\RuoRuoWatchdog\config.json（API 金鑰只存在這裡，不會進 repo）

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct AiConfig {
    /// "claude-cli"（Claude 訂閱）/ "codex-cli"（ChatGPT 訂閱）/ "anthropic-api"（API 金鑰）/ "none"
    pub provider: String,
    /// anthropic-api 用的模型
    pub model: String,
    /// anthropic-api 金鑰；留空則讀環境變數 ANTHROPIC_API_KEY
    pub api_key: String,
    /// 自動分析新出現、規則判定可疑的連線
    pub auto_analyze: bool,
    pub auto_interval_mins: u64,
    /// 傳給 AI 前把使用者資料夾路徑換成 %USERPROFILE%
    pub redact_paths: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        AiConfig {
            provider: "claude-cli".into(),
            model: "claude-opus-5-5".into(),
            api_key: String::new(),
            auto_analyze: false,
            auto_interval_mins: 30,
            redact_paths: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    pub port: u16,
    pub interval_secs: u64,
    /// 對 HTTPS 連線讀遠端憑證上的網域（查不到 DNS 時的備援）
    pub tls_probe: bool,
    pub ai: AiConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config { port: 8765, interval_secs: 5, tls_probe: true, ai: AiConfig::default() }
    }
}

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let d = base.join("RuoRuoWatchdog");
    let _ = std::fs::create_dir_all(&d);
    d
}

impl Config {
    pub fn load(dir: &Path) -> Config {
        std::fs::read_to_string(dir.join("config.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(dir.join("config.json"), s);
        }
    }

    pub fn api_key(&self) -> Option<String> {
        if !self.ai.api_key.trim().is_empty() {
            return Some(self.ai.api_key.trim().to_string());
        }
        std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.is_empty())
    }
}
