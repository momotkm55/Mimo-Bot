#![allow(dead_code)]
use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use std::fs::{File, OpenOptions};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

pub const VER: u32 = 113;

pub const MC_VER: &str = "1.1.5";

#[derive(Debug, Clone)]
pub struct ResourcePackEntry {
    pub id: String,
    pub version: String,
    pub size: u64,
}

#[derive(Debug)]
pub struct ResourcePacksInfo {
    pub must_accept: bool,
    pub behavior: Vec<ResourcePackEntry>,
    pub resources: Vec<ResourcePackEntry>,
}

#[derive(Debug)]
pub struct ResourcePackDataInfo {
    pub id: String,
    pub max_chunk_size: u32,
    pub chunk_count: u32,
    pub compressed_size: u64,
    pub sha256_len: usize,
}

#[derive(Debug)]
pub struct ResourcePackChunk {
    pub id: String,
    pub index: u32,
    pub progress: u64,
    pub data: Vec<u8>,
}

pub fn parse_packs(payload: &[u8]) -> Option<ResourcePacksInfo> {
    let mut offset = 1;
    let must_accept = *payload.get(offset)? != 0;
    offset += 1;
    let behavior_count = r2a(payload, &mut offset)? as usize;
    let behavior = parse_pack_list(payload, &mut offset, behavior_count)?;
    let resource_count = r2a(payload, &mut offset)? as usize;
    let resources = parse_pack_list(payload, &mut offset, resource_count)?;
    Some(ResourcePacksInfo {
        must_accept,
        behavior,
        resources,
    })
}

pub fn parse_pack_list(
    payload: &[u8],
    offset: &mut usize,
    count: usize,
) -> Option<Vec<ResourcePackEntry>> {
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id = rutf(payload, offset)?;
        let version = rutf(payload, offset)?;
        let size = r8a(payload, offset)?;
        entries.push(ResourcePackEntry { id, version, size });
    }
    Some(entries)
}

pub fn parse_pack_info(payload: &[u8]) -> Option<ResourcePackDataInfo> {
    let mut offset = 1;
    let id = rutf(payload, &mut offset)?;
    let max_chunk_size = r4a(payload, &mut offset)?;
    let chunk_count = r4a(payload, &mut offset)?;
    let compressed_size = r8a(payload, &mut offset)?;
    let sha256_len = rstr(payload, &mut offset)?.len();
    Some(ResourcePackDataInfo {
        id,
        max_chunk_size,
        chunk_count,
        compressed_size,
        sha256_len,
    })
}

pub fn parse_pack_chunk(payload: &[u8]) -> Option<ResourcePackChunk> {
    let mut offset = 1;
    let id = rutf(payload, &mut offset)?;
    let index = r4a(payload, &mut offset)?;
    let progress = r8a(payload, &mut offset)?;
    let data_len = r4a(payload, &mut offset)? as usize;
    let end = offset.checked_add(data_len)?;
    let data = payload.get(offset..end)?.to_vec();
    Some(ResourcePackChunk {
        id,
        index,
        progress,
        data,
    })
}

pub fn w3(out: &mut Vec<u8>, value: u32) {
    out.push((value & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push(((value >> 16) & 0xff) as u8);
}

pub fn w2b(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn w2(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn w4b(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn w4(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn wi4(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn wi8(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn wi8b(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn wvar(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut temp = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            temp |= 0x80;
        }
        out.push(temp);
        if value == 0 {
            break;
        }
    }
}

pub fn wvar8(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut temp = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            temp |= 0x80;
        }
        out.push(temp);
        if value == 0 {
            break;
        }
    }
}

pub fn wstr(out: &mut Vec<u8>, value: &[u8]) {
    wvar(out, value.len() as u32);
    out.extend_from_slice(value);
}

pub fn waddr(out: &mut Vec<u8>, addr: &SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => wsysaddr(out, v4.ip().octets(), v4.port()),
        SocketAddr::V6(_) => wsysaddr(out, [127, 0, 0, 1], addr.port()),
    }
}

pub fn wsysaddr(out: &mut Vec<u8>, ip: [u8; 4], port: u16) {
    out.push(4);
    for b in ip {
        out.push(!b);
    }
    w2b(out, port);
}

pub fn r3(data: &[u8], offset: usize) -> Option<u32> {
    Some(
        *data.get(offset)? as u32
            | ((*data.get(offset + 1)? as u32) << 8)
            | ((*data.get(offset + 2)? as u32) << 16),
    )
}

pub fn ri8b(data: &[u8], offset: usize) -> Option<i64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(i64::from_be_bytes(bytes))
}

pub fn r4b(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

pub fn r2a(data: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes: [u8; 2] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(u16::from_le_bytes(bytes))
}

pub fn r4a(data: &[u8], offset: &mut usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(u32::from_le_bytes(bytes))
}

pub fn r8a(data: &[u8], offset: &mut usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(u64::from_le_bytes(bytes))
}

pub fn rf4(data: &[u8], offset: usize) -> Option<f32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(f32::from_le_bytes(bytes))
}

pub fn rvar(data: &[u8], offset: &mut usize) -> Option<u32> {
    let mut value = 0u32;
    let mut shift = 0;
    loop {
        let byte = *data.get(*offset)?;
        *offset += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

pub fn rvari(data: &[u8], offset: &mut usize) -> Option<i32> {
    let raw = rvar(data, offset)?;
    Some(((raw >> 1) as i32) ^ (-((raw & 1) as i32)))
}

pub fn rstr(data: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
    let len = rvar(data, offset)? as usize;
    let end = offset.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let value = data[*offset..end].to_vec();
    *offset = end;
    Some(value)
}

pub fn rutf(data: &[u8], offset: &mut usize) -> Option<String> {
    let bytes = rstr(data, offset)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn rrakstr(data: &[u8], offset: usize) -> Option<String> {
    let len = u16::from_be_bytes([*data.get(offset)?, *data.get(offset + 1)?]) as usize;
    let bytes = data.get(offset + 2..offset + 2 + len)?;
    Some(String::from_utf8_lossy(bytes).to_string())
}

pub fn pkt_name(id: u8) -> &'static str {
    match id {
        0x01 => "Login",
        0x02 => "PlayStatus",
        0x03 => "ServerToClientHandshake",
        0x04 => "ClientToServerHandshake",
        0x05 => "Disconnect",
        0x06 => "ResourcePacksInfo",
        0x07 => "ResourcePackStack",
        0x08 => "ResourcePackClientResponse",
        0x09 => "Text",
        0x0a => "SetTime",
        0x0b => "StartGame",
        0x13 => "MovePlayer",
        0x1e => "UpdateAttributes",
        0x24 => "PlayerAction",
        0x35 => "CraftingData",
        0x37 => "AdventureSettings",
        0x38 => "SetEntityData",
        0x39 => "PlayerInput",
        0x3a => "FullChunkData",
        0x3f => "PlayerList",
        0x45 => "RequestChunkRadius",
        0x46 => "ChunkRadiusUpdated",
        0x4e => "AvailableCommands",
        0x4f => "CommandStep",
        0x53 => "ResourcePackDataInfo",
        0x54 => "ResourcePackChunkData",
        0x55 => "ResourcePackChunkRequest",
        0x59 => "SetTitle",
        0xfe => "Batch",
        _ => "Неизвестно",
    }
}

pub fn rak_name(id: u8) -> &'static str {
    match id {
        0x01 => "UnconnectedPing",
        0x05 => "OpenConnectionRequest1",
        0x06 => "OpenConnectionReply1",
        0x07 => "OpenConnectionRequest2",
        0x08 => "OpenConnectionReply2",
        0x19 => "IncompatibleProtocol",
        0x1c => "UnconnectedPong",
        0x80..=0x8f => "Datagram",
        0xa0 => "NACK",
        0xc0 => "ACK",
        _ => "Неизвестно",
    }
}

pub fn txt_type(text_type: u8) -> &'static str {
    match text_type {
        0 => "text",
        1 => "chat",
        2 => "translation",
        3 => "popup",
        4 => "tip",
        5 => "system",
        6 => "whisper",
        _ => "text",
    }
}

pub fn title_type(title_type: u32) -> &'static str {
    match title_type {
        0 => "title-clear",
        1 => "title-reset",
        2 => "title",
        3 => "subtitle",
        4 => "actionbar",
        5 => "title-times",
        6 => "title-extra",
        _ => "title",
    }
}

pub fn pkt_id_str(bytes: &[u8]) -> String {
    bytes
        .first()
        .map(|id| format!("0x{id:02x}"))
        .unwrap_or_else(|| "пустой пакет".to_string())
}

pub fn clean_line(line: &str) -> String {
    let mut out = Vec::new();
    let mut blank = false;
    for (idx, raw) in line.replace('\r', "\n").lines().enumerate() {
        let cleaned = if idx == 0 && raw.starts_with('[') {
            if let Some(end) = raw.find("] ") {
                let prefix = &raw[..=end];
                let rest = raw[end + 2..].trim();
                if rest.is_empty() {
                    prefix.to_string()
                } else {
                    format!("{prefix} {rest}")
                }
            } else {
                raw.trim().to_string()
            }
        } else {
            raw.trim().to_string()
        };
        if cleaned.is_empty() {
            if !blank && !out.is_empty() {
                out.push(String::new());
                blank = true;
            }
        } else {
            out.push(cleaned);
            blank = false;
        }
    }
    while out.last().is_some_and(|line| line.is_empty()) {
        out.pop();
    }
    trim_str(&out.join("\n"), 1600)
}

pub fn jesc(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

pub fn hex_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(64)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn trim_str(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().take(max_chars) {
        out.push(ch);
    }
    if value.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

pub fn dc_reason(payload: &[u8]) -> String {
    if payload.len() >= 3 {
        let mut offset = 2;
        if let Some(len) = rvar(payload, &mut offset) {
            let len = len as usize;
            if let Some(message) = payload.get(offset..offset + len) {
                return String::from_utf8_lossy(message).to_string();
            }
        }
    }
    if payload.len() >= 3 {
        let len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
        if let Some(message) = payload.get(3..3 + len) {
            return String::from_utf8_lossy(message).to_string();
        }
    }
    hex_str(payload)
}

pub fn cmd_payload(command_line: &str, split_args: bool) -> (String, String) {
    if !split_args {
        return (command_line.to_string(), "[]".to_string());
    }
    let mut parts = command_line.split_whitespace();
    let command = parts.next().unwrap_or(command_line).to_string();
    let args: Vec<String> = parts.map(str::to_string).collect();
    (command, jarr(&args))
}

pub fn jarr(values: &[String]) -> String {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        jpush(&mut out, value);
    }
    out.push(']');
    out
}

pub fn jpush(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

pub fn pkt_info(payload: &[u8]) -> String {
    let Some(id) = payload.first().copied() else {
        return String::new();
    };
    match id {
        0x01 => format!("protocol={VER}"),
        0x08 => {
            let status = payload.get(1).copied().unwrap_or(0);
            let label = match status {
                1 => "REFUSED",
                2 => "SEND_PACKS",
                3 => "HAVE_ALL_PACKS",
                4 => "COMPLETED",
                _ => "UNKNOWN",
            };
            let count = payload
                .get(2..4)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .unwrap_or(0);
            format!("status={label}({status}) packs={count}")
        }
        0x09 => {
            let mut offset = 1;
            let text_type = payload.get(offset).copied().unwrap_or(0);
            offset += 1;
            if text_type == 1 {
                let _ = rutf(payload, &mut offset);
                if let Some(message) = rutf(payload, &mut offset) {
                    return format!("chat={}", trim_str(&message, 80));
                }
            }
            String::new()
        }
        0x13 => "movement".to_string(),
        0x37 => "auto_jump".to_string(),
        0x39 => "input idle".to_string(),
        0x45 => {
            let mut offset = 1;
            match rvar(payload, &mut offset) {
                Some(radius) => format!("radius={radius}"),
                None => String::new(),
            }
        }
        0x4f => {
            let mut offset = 1;
            match rutf(payload, &mut offset) {
                Some(command) => format!("command=/{}", trim_str(&command, 80)),
                None => String::new(),
            }
        }
        0x55 => {
            let mut offset = 1;
            let id = rutf(payload, &mut offset).unwrap_or_default();
            let chunk = r4a(payload, &mut offset).unwrap_or(0);
            format!("pack={} chunk={chunk}", trim_str(&id, 48))
        }
        _ => String::new(),
    }
}

pub fn ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn sec_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn gen_uuid(name: &str) -> String {
    let mut hash: u128 = 0x1234_5678_9abc_def0_1357_2468_ace0_bdf1;
    for &b in name.as_bytes() {
        hash ^= b as u128;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
        hash = hash.rotate_left(7);
    }
    hash &= !(0xfu128 << 76);
    hash |= 3u128 << 76;
    hash &= !(0x3u128 << 62);
    hash |= 0x2u128 << 62;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (hash >> 96) as u32,
        (hash >> 80) as u16,
        (hash >> 64) as u16,
        (hash >> 48) as u16,
        hash & 0x0000_ffff_ffff_ffff
    )
}

pub fn gen_id(seed: &str) -> i64 {
    let mut value = ms_now() as u64 ^ 0x9e37_79b9_7f4a_7c15;
    for &byte in seed.as_bytes() {
        value ^= byte as u64;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
    }
    value as i64
}

pub fn gen_xuid(seed: &str) -> String {
    let mut value = 0x243f_6a88_85a3_08d3u64;
    for &byte in seed.as_bytes() {
        value ^= byte as u64;
        value = value.wrapping_mul(0x9e37_79b1_85eb_ca87);
        value ^= value >> 29;
    }
    let value = 1_000_000_000_000_000u64 + (value % 8_000_000_000_000_000u64);
    value.to_string()
}

pub fn spawn_chunks(view_distance: u32) -> u32 {
    let radius = view_distance.clamp(1, 4) as f64;
    ((radius * radius * std::f64::consts::PI) as u32).max(1)
}

pub fn fix_name(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars().take(80) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "target".to_string()
    } else {
        out
    }
}

pub fn dump_paths(host: &str, name: &str, server: &SocketAddr) -> (String, String) {
    let host = fix_name(host);
    let resolved = fix_name(&server.to_string());
    let name = fix_name(name);
    let stamp = ms_now();
    (
        format!("target/mcpe113_{host}_{resolved}_{name}_{stamp}.log"),
        format!("target/raknet_raw_{host}_{resolved}_{name}_{stamp}.log"),
    )
}

#[allow(dead_code)]
pub fn open_log(path: &str) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .or_else(|_| {
            std::fs::create_dir_all("target")?;
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
        })
}

pub fn open_pkt_log(_path: &str) -> io::Result<File> {
    if cfg!(windows) {
        OpenOptions::new().write(true).open("NUL")
    } else {
        OpenOptions::new().write(true).open("/dev/null")
    }
}

pub fn to_addr(host: &str, port: u16) -> io::Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "адрес не найден"))
}

pub fn start_input() -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if tx.send(line).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    });
    rx
}

pub fn b64s(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = *data.get(i + 1).unwrap_or(&0);
        let b2 = *data.get(i + 2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < data.len() {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

pub fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64d(input: &str) -> Option<Vec<u8>> {
    B64_STANDARD
        .decode(input)
        .or_else(|_| URL_SAFE_NO_PAD.decode(input))
        .ok()
}

pub fn player_like_skin(_name: &str) -> Vec<u8> {
    vec![0u8; 64 * 32 * 4]
}

pub use self::b64d as b64_decode_any;
pub use self::b64s as b64_std;
pub use self::b64u as b64_url_no_pad;
pub use self::clean_line as clean_console_line;
pub use self::cmd_payload as command_step_payload;
pub use self::dc_reason as describe_disconnect;

pub use self::fix_name as sanitize_dump_part;
pub use self::gen_id as random_client_id;
pub use self::gen_uuid as offline_uuid;
pub use self::gen_xuid as fake_xuid;
pub use self::hex_str as describe_bytes;
pub use self::jesc as json_escape;

pub use self::parse_pack_chunk as parse_resource_pack_chunk_data;
pub use self::parse_pack_info as parse_resource_pack_data_info;
pub use self::parse_packs as parse_resource_packs_info;
pub use self::pkt_id_str as packet_id_text;

pub use self::pkt_name as packet_name;
pub use self::r3 as read_triad_le;
pub use self::r4b as read_u32_be;
pub use self::rak_name as raknet_packet_name;
pub use self::rf4 as read_f32_le;
pub use self::ri8b as read_i64_be;
pub use self::rrakstr as read_rak_string;
pub use self::rstr as read_mcpe_string;
pub use self::rutf as read_mcpe_utf8_string;
pub use self::rvar as read_var_u32;
pub use self::sec_now as now_secs;
pub use self::spawn_chunks as estimated_spawn_chunks;

pub use self::title_type as set_title_type_name;

pub use self::trim_str as trim_for_log;
pub use self::txt_type as text_type_name;
pub use self::w2 as put_u16_le;
pub use self::w2b as put_u16_be;
pub use self::w3 as put_triad_le;
pub use self::w4 as put_u32_le;
pub use self::w4b as put_u32_be;
pub use self::waddr as put_addr;
pub use self::wi8b as put_i64_be;
pub use self::wstr as put_mcpe_string;
pub use self::wsysaddr as put_system_addr;
pub use self::wvar as put_var_u32;
pub use self::wvar8 as put_var_u64;