pub mod client;
pub mod colors;
pub mod config;
pub mod crypto;
pub mod log;
pub mod proto;
pub mod raknet;

use client::{make_login_packet, Client, MTU, INTERRUPTED};
use config::Device;
use log::{banner, bot, cmd_exit, err, start, user};
use crypto::AuthKey;
use proto::{ms_now, open_pkt_log, to_addr};
use rand::Rng;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::CStr;
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};


fn setup_ctrlc_handler() {
    ctrlc::set_handler(|| {
        INTERRUPTED.store(true, Ordering::SeqCst);
    })
    .ok();
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub protocol: u32,
    pub multi_bot: bool,
    pub multi_bot_count: u32,
}

#[no_mangle]
pub extern "C" fn RunBot(host_ptr: *const c_char, port: c_int, name_ptr: *const c_char) -> i32 {
    if host_ptr.is_null() {
        return 1;
    }

    let host = unsafe {
        match CStr::from_ptr(host_ptr).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return 2,
        }
    };

    let name = if name_ptr.is_null() {
        "CalvynBot".to_string()
    } else {
        unsafe {
            match CStr::from_ptr(name_ptr).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => "CalvynBot".to_string(),
            }
        }
    };

    let cfg = Config {
        host,
        port: port as u16,
        name,
        protocol: proto::VER,
        multi_bot: false,
        multi_bot_count: 10,
    };

    match run_client(cfg) {
        Ok(_) => 0,
        Err(e) => {
            err(&e.to_string());
            3
        }
    }
}

pub fn run_client(cfg: Config) -> io::Result<()> {
    let server = to_addr(&cfg.host, cfg.port)?;
    banner();
    start(&cfg.host, cfg.port, &cfg.name);
    setup_ctrlc_handler();

    if cfg.multi_bot {
        run_multi_bot(cfg, server)
    } else {
        run_single_bot(cfg, server)
    }
}

fn run_single_bot(cfg: Config, server: SocketAddr) -> io::Result<()> {
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            break;
        }

        bot("подключение к серверу...");

        let auth = AuthKey::new();
        let dev = Device::load();
        let login_packet = make_login_packet(&cfg.host, cfg.port, &cfg.name, &auth, cfg.protocol, &dev);

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;

        let guid = ms_now() as i64 ^ 0x1130_0000_0000_0000u64 as i64;

        let mut client = Client {
            socket,
            server,
            auth,
            name: cfg.name.clone(),
            guid,
            srv_guid: 0,
            mtu: MTU,
            seq: 0,
            rel_idx: 0,
            ord_idx: 0,
            ord_idxs: HashMap::new(),
            ord_frames: BTreeMap::new(),
            split_id: 1,
            splits: HashMap::new(),
            pending: HashMap::new(),
            enc: None,
            bad_enc: 0,
            bad_batch: 0,
            resend_log_count: 0,
            in_cnt: HashMap::new(),
            out_cnt: HashMap::new(),
            text_line_counts: HashMap::new(),
            pack_ids: Vec::new(),
            packs: HashMap::new(),
            sent_have_all_packs: false,
            pending_chat: VecDeque::new(),
            joined: false,
            disconnected: false,
            sent_client_handshake: false,
            sent_chunk_radius: false,
            saw_start_game: false,
            first_chunk_at: None,
            last_chunk_at: None,
            entity_runtime_id: 0,
            pos: (0.0, 64.0, 0.0),
            yaw: 0.0,
            pitch: 0.0,
            dump: open_pkt_log("")?,
            raw_dump: open_pkt_log("")?,
            start: Instant::now(),
            chunk_radius: 8,
            spawn_fallback_ms: 8000,
            chat_interval_ms: 2500,
            chat_quiet_ms: 700,
            post_auth_delay_ms: 4500,
            chat_raw: false,
            chat_no_source: false,
            chat_source_name: true,
            chat_reliability: 3,
            command_step_for_slash: false,
            command_step_split_args: true,
            last_chat_sent_at: None,
            last_chat_wait_log_at: None,
            last_auth_transition_at: None,
            split_chunk: None,
            world_exporter: None,
            scan_radius_chunks: 0,
            scan_interval_ms: 180,
            protocol: cfg.protocol,
            scan_path: Vec::new(),
            scan_index: 0,
            scan_complete_at: None,
            scan_idle_finish_ms: 6000,
            finish_after_scan: false,
            dashboard: false,
            event_log: VecDeque::new(),
            status_text: "connecting".to_string(),
            last_text_line: String::new(),
            spawn_x: 0.0,
            spawn_z: 0.0,
            movement_phase: 0,
            last_movement_at: None,
            movement_enabled: true,
            show_output: Arc::new(AtomicBool::new(true)),
        };

        let mut rng = rand::thread_rng();
        let (tx, rx) = mpsc::channel::<String>();

        let exit_tx = tx.clone();
        thread::spawn(move || loop {
            let mut line = String::new();
            if io::stdin().read_line(&mut line).is_ok() {
                let trimmed = line.trim().to_string();
                if trimmed == "/exit" || trimmed == "/quit" {
                    cmd_exit();
                    io::stdout().flush().ok();
                    let _ = exit_tx.send("__EXIT__".to_string());
                    break;
                }
                if !trimmed.is_empty() {
                    user(&trimmed);
                    io::stdout().flush().ok();
                    if tx.send(trimmed).is_err() {
                        break;
                    }
                }
            } else {
                break;
            }
        });

        let result = (|| -> io::Result<()> {
            client.ping()?;
            thread::sleep(Duration::from_millis(rng.gen_range(100..300)));
            client.connect()?;
            thread::sleep(Duration::from_millis(rng.gen_range(200..500)));
            client.handshake()?;
            thread::sleep(Duration::from_millis(rng.gen_range(300..800)));
            client.login(login_packet)?;
            thread::sleep(Duration::from_millis(rng.gen_range(500..1500)));
            client.run(0, Some(rx), None)?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                let _ = client.disconnect();
                bot(&format!("отключился, был в сети {} сек.", client.start.elapsed().as_secs()));
            }
            Err(e) => {
                err(&format!("ошибка: {}", e));
                bot(&format!("был в сети {} сек.", client.start.elapsed().as_secs()));
            }
        }

        if INTERRUPTED.load(Ordering::SeqCst) {
            break;
        }

        let reconnect_secs = 5;
        bot(&format!("переподключение через {} сек...", reconnect_secs));
        for _ in 0..reconnect_secs * 10 {
            if INTERRUPTED.load(Ordering::SeqCst) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    bot("завершён");
    Ok(())
}

fn run_multi_bot(cfg: Config, server: SocketAddr) -> io::Result<()> {
    let count = cfg.multi_bot_count.max(1).min(100);
    bot(&format!("мульти-бот режим: {} ботов", count));

    let (chat_tx, chat_rx) = mpsc::channel::<(usize, String)>();

    let stdin_tx = chat_tx.clone();
    thread::spawn(move || loop {
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_ok() {
            let trimmed = line.trim().to_string();
            if trimmed == "/exit" || trimmed == "/quit" {
                cmd_exit();
                io::stdout().flush().ok();
                break;
            }
            if !trimmed.is_empty() {
                user(&trimmed);
                io::stdout().flush().ok();
                if stdin_tx.send((0, trimmed)).is_err() {
                    break;
                }
            }
        } else {
            break;
        }
    });

    let mut bots: Vec<Option<mpsc::Sender<String>>> = Vec::new();
    let mut bot_outputs: Vec<Arc<AtomicBool>> = Vec::new();
    let mut primary_idx: usize = 0;

    for i in 0..count {
        let bot_idx = i as usize;
        let suffix = format!("_{:03}", i + 1);
        let name = format!("{}{}", cfg.name, suffix);
        bot(&format!("создаём бота #{} ({})", i, name));

        let auth = AuthKey::new();
        let dev = Device::load();
        let login_packet = make_login_packet(&cfg.host, cfg.port, &name, &auth, cfg.protocol, &dev);

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;

        let guid = ms_now() as i64 ^ 0x1130_0000_0000_0000u64 as i64;

            let output_flag = Arc::new(AtomicBool::new(bot_idx == 0));
            let output_flag_clone = output_flag.clone();

            let mut client = Client {
            socket,
            server,
            auth,
            name: name.clone(),
            guid,
            srv_guid: 0,
            mtu: MTU,
            seq: 0,
            rel_idx: 0,
            ord_idx: 0,
            ord_idxs: HashMap::new(),
            ord_frames: BTreeMap::new(),
            split_id: 1,
            splits: HashMap::new(),
            pending: HashMap::new(),
            enc: None,
            bad_enc: 0,
            bad_batch: 0,
            resend_log_count: 0,
            in_cnt: HashMap::new(),
            out_cnt: HashMap::new(),
            text_line_counts: HashMap::new(),
            pack_ids: Vec::new(),
            packs: HashMap::new(),
            sent_have_all_packs: false,
            pending_chat: VecDeque::new(),
            joined: false,
            disconnected: false,
            sent_client_handshake: false,
            sent_chunk_radius: false,
            saw_start_game: false,
            first_chunk_at: None,
            last_chunk_at: None,
            entity_runtime_id: 0,
            pos: (0.0, 64.0, 0.0),
            yaw: 0.0,
            pitch: 0.0,
            dump: open_pkt_log("")?,
            raw_dump: open_pkt_log("")?,
            start: Instant::now(),
            chunk_radius: 8,
            spawn_fallback_ms: 8000,
            chat_interval_ms: 2500,
            chat_quiet_ms: 700,
            post_auth_delay_ms: 4500,
            chat_raw: false,
            chat_no_source: false,
            chat_source_name: true,
            chat_reliability: 3,
            command_step_for_slash: false,
            command_step_split_args: true,
            last_chat_sent_at: None,
            last_chat_wait_log_at: None,
            last_auth_transition_at: None,
            split_chunk: None,
            world_exporter: None,
            scan_radius_chunks: 0,
            scan_interval_ms: 180,
            protocol: cfg.protocol,
            scan_path: Vec::new(),
            scan_index: 0,
            scan_complete_at: None,
            scan_idle_finish_ms: 6000,
            finish_after_scan: false,
            dashboard: false,
            event_log: VecDeque::new(),
            status_text: "connecting".to_string(),
            last_text_line: String::new(),
            spawn_x: 0.0,
            spawn_z: 0.0,
            movement_phase: 0,
            last_movement_at: None,
            movement_enabled: true,
            show_output: output_flag_clone,
        };

        let (tx, rx) = mpsc::channel::<String>();

        let bot_chat_tx = chat_tx.clone();
        let is_primary = bot_idx == 0;

        thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let result = (|| -> io::Result<()> {
                client.ping()?;
                thread::sleep(Duration::from_millis(rng.gen_range(100..300)));
                client.connect()?;
                thread::sleep(Duration::from_millis(rng.gen_range(200..500)));
                client.handshake()?;
                thread::sleep(Duration::from_millis(rng.gen_range(300..800)));
                client.login(login_packet)?;
                thread::sleep(Duration::from_millis(rng.gen_range(500..1500)));
                client.run(0, Some(rx), None)?;
                Ok(())
            })();

            match result {
                Ok(()) => {
                    let _ = client.disconnect();
                    if is_primary {
                        bot(&format!("[bot #{}] отключился, был в сети {} сек.", bot_idx, client.start.elapsed().as_secs()));
                    }
                }
                Err(e) => {
                    err(&format!("[bot #{}] ошибка: {}", bot_idx, e));
                }
            }

            let _ = bot_chat_tx.send((bot_idx, format!("__DISCONNECTED__{}", bot_idx)));
        });

        bots.push(Some(tx));
        bot_outputs.push(output_flag);
        thread::sleep(Duration::from_millis(100));
    }

    bot(&format!("все {} ботов запущены", count));
    bot("команды: connect <id>, disconnect, move <x> <y> <z>, stop");

    while !INTERRUPTED.load(Ordering::SeqCst) {
        while let Ok((sender_idx, message)) = chat_rx.try_recv() {
            if message == "__EXIT__" {
                for bot_opt in &mut bots {
                    if let Some(tx) = bot_opt.take() {
                        let _ = tx.send("__EXIT__".to_string());
                    }
                }
                return Ok(());
            }

            if sender_idx == 0 {
                let args: Vec<&str> = message.split_whitespace().collect();
                match args.first().map(|s| *s) {
                    Some("stop") => {
                        bot("останавливаем всех ботов...");
                        for bot_opt in &mut bots {
                            if let Some(tx) = bot_opt.take() {
                                let _ = tx.send("__EXIT__".to_string());
                            }
                        }
                        return Ok(());
                    }
                    Some("connect") => {
                        if let Some(id_str) = args.get(1) {
                            if let Ok(id) = id_str.parse::<usize>() {
                                if id < bots.len() {
                                    primary_idx = id;
                                    bot(&format!("чат переключен на бота #{}", id));
                                } else {
                                    bot(&format!("бот #{} не существует", id));
                                }
                            }
                        } else {
                            bot("использование: connect <id>");
                        }
                    }
                    Some("disconnect") => {
                        bot("чат отключен от бота");
                        primary_idx = 0;
                    }
                    _ => {
                        for bot_opt in bots.iter() {
                            if let Some(tx) = bot_opt {
                                let _ = tx.send(message.clone());
                            }
                        }
                    }
                }
            } else {
                let parts: Vec<&str> = message.splitn(2, "__DISCONNECTED__").collect();
                if parts.len() == 2 {
                    if let Ok(disconn_id) = parts[1].parse::<usize>() {
                        if disconn_id == primary_idx {
                            bot_outputs[primary_idx].store(false, Ordering::Relaxed);
                            for j in 0..bots.len() {
                                if bots[j].is_some() && j != disconn_id {
                                    primary_idx = j;
                                    bot_outputs[j].store(true, Ordering::Relaxed);
                                    bot(&format!("чат переключен на бота #{}", j));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    for bot_opt in &mut bots {
        if let Some(tx) = bot_opt.take() {
            let _ = tx.send("__EXIT__".to_string());
        }
    }

    bot("мульти-бот завершён");
    Ok(())
}
