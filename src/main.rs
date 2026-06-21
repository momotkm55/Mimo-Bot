use calvyn_mcpe_bot::proto::{ms_now, VER};
use calvyn_mcpe_bot::{run_client, Config};
use std::io;

fn main() -> io::Result<()> {
    let cfg = parse_args();

    if cfg.host.is_empty() {
        return Ok(());
    }
    run_client(cfg)
}

fn parse_args() -> Config {
    let mut cfg = Config {
        host: String::new(),
        port: 19132,
        name: format!("CalvynBot{:04}", ms_now() % 10_000),
        protocol: VER,
        multi_bot: false,
        multi_bot_count: 10,
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" => {
                if let Some(value) = args.next() {
                    cfg.host = value;
                }
            }
            "-p" => {
                if let Some(value) = args.next() {
                    cfg.port = value.parse().unwrap_or(cfg.port);
                }
            }
            "-n" => {
                if let Some(value) = args.next() {
                    cfg.name = value;
                }
            }
            "--multi-bot" => {
                cfg.multi_bot = true;
            }
            "--multi-bot-count" => {
                if let Some(value) = args.next() {
                    cfg.multi_bot_count = value.parse().unwrap_or(cfg.multi_bot_count);
                }
            }
            _ => {}
        }
    }
    cfg
}
