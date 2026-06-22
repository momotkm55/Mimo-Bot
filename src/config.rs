use std::fs;

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Device {
    #[serde(default)]
    pub device_id: String,
    #[serde(default = "default_model")]
    pub device_model: String,
    #[serde(default = "default_os")]
    pub device_os: i32,
    #[serde(default = "default_game_ver")]
    pub game_version: String,
    #[serde(default = "default_skin")]
    pub skin_id: String,
    #[serde(default = "default_lang")]
    pub language: String,
    #[serde(default)]
    pub multi_bot: bool,
    #[serde(default = "default_multi_bot_count")]
    pub multi_bot_count: u32,
}

impl Device {
    pub fn load() -> Self {
        let data = fs::read_to_string("config.json").unwrap_or_default();
        let mut dev: Device = serde_json::from_str(&data).unwrap_or_default();
        if dev.device_id.is_empty() {
            dev.device_id = gen_id();
        }
        dev
    }
}

impl Default for Device {
    fn default() -> Self {
        Self {
            device_id: gen_id(),
            device_model: default_model(),
            device_os: default_os(),
            game_version: default_game_ver(),
            skin_id: default_skin(),
            language: default_lang(),
            multi_bot: false,
            multi_bot_count: default_multi_bot_count(),
        }
    }
}

fn default_model() -> String { "SAMSUNG SM-G935F".to_string() }
fn default_os() -> i32 { 1 }
fn default_game_ver() -> String { "1.1.5".to_string() }
fn default_skin() -> String { "Standard_Custom".to_string() }
fn default_lang() -> String { "en_US".to_string() }
fn default_multi_bot_count() -> u32 { 10 }

fn gen_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", now)
}