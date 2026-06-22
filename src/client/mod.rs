#![allow(dead_code)]
#![allow(unused_variables)]

pub mod packets;
pub mod skin;
pub mod terminal;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub use packets::make_login_packet;
pub use terminal::LiveTerminal;

pub use skin::{flat_skin, player_like_skin};

pub const MTU: u16 = 1400;
pub const RAK_VER: u8 = 8;

pub const MAGIC_BYTES: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

use crate::colors::mc_to_ansi;
use crate::crypto::{AuthKey, EncryptionState};
use crate::log::{srv, bot, rak, net, cry, err};
use crate::proto::{
    clean_console_line, command_step_payload, describe_bytes, describe_disconnect,
    estimated_spawn_chunks, packet_id_text, packet_name, parse_resource_pack_chunk_data, parse_resource_pack_data_info,
    parse_resource_packs_info, put_addr, put_i64_be, put_mcpe_string, put_system_addr,
    put_triad_le, put_u16_be, put_u16_le, put_u32_be, put_u32_le, put_var_u32, put_var_u64,
    raknet_packet_name, read_f32_le, read_i64_be, read_mcpe_string,
    read_mcpe_utf8_string, read_rak_string, read_triad_le, read_u32_be, read_var_u32,
    sanitize_dump_part, set_title_type_name, text_type_name, trim_for_log,
};
use crate::raknet::{
    frame_header_len, parse_ack_records, parse_frames, Frame, PendingDatagram, SplitBuffer,
};


use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::Receiver;

use std::time::{Duration, Instant};

pub struct PackDl {
    pub max_chunk_size: u32,
    pub chunk_count: u32,
    pub compressed_size: u64,
    pub received_count: u32,
    pub next_request: u32,
    pub in_flight: u32,
    pub chunks: Vec<Option<Vec<u8>>>,
    pub saved: bool,
}

impl PackDl {
    pub fn complete(&self) -> bool {
        self.received_count >= self.chunk_count
    }
}

pub struct Client {
    pub socket: UdpSocket,
    pub server: SocketAddr,
    pub auth: AuthKey,
    pub name: String,
    pub guid: i64,
    pub srv_guid: i64,
    pub mtu: u16,
    pub seq: u32,
    pub rel_idx: u32,
    pub ord_idx: u32,
    pub ord_idxs: HashMap<u8, u32>,
    pub ord_frames: BTreeMap<(u8, u32), Frame>,
    pub split_id: u16,
    pub splits: HashMap<u16, SplitBuffer>,
    pub pending: HashMap<u32, PendingDatagram>,
    pub enc: Option<EncryptionState>,
    pub bad_enc: u32,
    pub bad_batch: u32,
    pub resend_log_count: u32,
    pub in_cnt: HashMap<u8, u32>,
    pub out_cnt: HashMap<u8, u32>,
    pub text_line_counts: HashMap<String, u32>,
    pub pack_ids: Vec<String>,
    pub packs: HashMap<String, PackDl>,
    pub sent_have_all_packs: bool,
    pub pending_chat: VecDeque<String>,
    pub joined: bool,
    pub disconnected: bool,
    pub sent_client_handshake: bool,
    pub sent_chunk_radius: bool,
    pub saw_start_game: bool,
    pub first_chunk_at: Option<Instant>,
    pub last_chunk_at: Option<Instant>,
    pub entity_runtime_id: i32,
    pub pos: (f32, f32, f32),
    pub yaw: f32,
    pub pitch: f32,
    pub dump: File,
    pub raw_dump: File,
    pub start: Instant,
    pub chunk_radius: u32,
    pub spawn_fallback_ms: u64,
    pub chat_interval_ms: u64,
    pub chat_quiet_ms: u64,
    pub post_auth_delay_ms: u64,
    pub chat_raw: bool,
    pub chat_no_source: bool,
    pub chat_source_name: bool,
    pub chat_reliability: u8,
    pub command_step_for_slash: bool,
    pub command_step_split_args: bool,
    pub last_chat_sent_at: Option<Instant>,
    pub last_chat_wait_log_at: Option<Instant>,
    pub last_auth_transition_at: Option<Instant>,
    pub split_chunk: Option<usize>,
    pub world_exporter: Option<()>,
    pub scan_radius_chunks: i32,
    pub scan_interval_ms: u64,
    pub scan_path: Vec<(f32, f32)>,
    pub scan_index: usize,
    pub scan_complete_at: Option<Instant>,
    pub scan_idle_finish_ms: u64,
    pub finish_after_scan: bool,
    pub dashboard: bool,
    pub event_log: VecDeque<String>,
    pub status_text: String,
    pub last_text_line: String,
    pub protocol: u32,
    pub spawn_x: f32,
    pub spawn_z: f32,
    pub movement_phase: u32,
    pub last_movement_at: Option<Instant>,
    pub movement_enabled: bool,
    pub show_output: Arc<AtomicBool>,
    pub last_recv_at: Option<Instant>,
    pub keepalive_timeout_secs: u64,
    pub dump_enabled: bool,
}

impl Client {
    pub fn init_log(&mut self, host: &str, port: u16, name: &str) -> io::Result<()> {
        let raknet_version = RAK_VER;
        let game_version = "1.1.5";
        let header = format!(
            "# target={}:{} resolved={} name={} protocol={} game_version={} raknet={} mtu={}",
            host, port, self.server, name, self.protocol, game_version, raknet_version, self.mtu
        );
        writeln!(self.dump, "{header}")?;
        writeln!(self.raw_dump, "{header}")?;
        Ok(())
    }

    pub fn ping(&mut self) -> io::Result<()> {
        let mut ping = Vec::with_capacity(33);
        ping.push(0x01);
        put_i64_be(&mut ping, self.elapsed_ms());
        ping.extend_from_slice(&MAGIC_BYTES);
        put_i64_be(&mut ping, self.guid);
        self.send_raw(&ping)?;

        let buf = self.recv()?;
        if buf.first() != Some(&0x1c) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ожидал пинг 0x1c, а пришел {}",
                    packet_id_text(&buf)
                ),
            ));
        }
        self.srv_guid = read_i64_be(&buf, 9).unwrap_or(0);
        if let Some(motd) = read_rak_string(&buf, 33) {
            srv(&motd);
        }
        Ok(())
    }

    pub fn connect(&mut self) -> io::Result<()> {
        let raknet_protocol = RAK_VER;
        let mtu_candidates = vec![1400u16, 1200, 576, 548];
        let mut last_err = None;
        for mtu in mtu_candidates {
            self.mtu = mtu;
            match self.open_connection_mtu(raknet_protocol, mtu) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "не удалось установить ракнет",
            )
        }))
    }

    fn open_connection_mtu(&mut self, raknet_protocol: u8, mtu: u16) -> io::Result<()> {
        rak(&format!("пробуем mtu={} protocol={}", mtu, raknet_protocol));
        let mut req1 = Vec::new();
        req1.push(0x05);
        req1.extend_from_slice(&MAGIC_BYTES);
        req1.push(raknet_protocol);
        req1.resize(mtu as usize, 0);
        self.send_raw(&req1)?;

        let reply1 = self.recv_open1_reply(&req1)?;
        rak("получаем OpenConnectionReply1");
        if reply1.len() >= 28 {
            self.srv_guid = read_i64_be(&reply1, 17).unwrap_or(self.srv_guid);
            let server_mtu = u16::from_be_bytes([reply1[26], reply1[27]]);
            self.mtu = server_mtu.min(1400).max(548);
        }
        rak(&format!("соединение установлено, mtu {}", self.mtu));

        let mut req2 = Vec::new();
        req2.push(0x07);
        req2.extend_from_slice(&MAGIC_BYTES);
        put_addr(&mut req2, &self.server);
        put_u16_be(&mut req2, self.mtu);
        put_i64_be(&mut req2, self.guid);
        rak(&format!("пакет OpenConnectionRequest2: {} байт", req2.len()));
        self.send_raw(&req2)?;
        rak("отправляем OpenConnectionRequest2");

        match self.recv_open2_reply(&req2) {
            Ok(reply2) => {
                rak("получаем OpenConnectionReply2");
                if reply2.len() >= 18 {
                    self.srv_guid = read_i64_be(&reply2, 17).unwrap_or(self.srv_guid);
                }
            }
            Err(e) => {
                err(&format!("ошибка в функции recv_open2_reply: {}", e));
                return Err(e);
            }
        }
        Ok(())
    }

    fn recv_open1_reply(&mut self, req1: &[u8]) -> io::Result<Vec<u8>> {
        let mut answered_challenge = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        self.socket.set_read_timeout(Some(Duration::from_millis(800)))?;
        let mut _retries = 0;
        while Instant::now() < deadline {
            let reply = match self.recv() {
                Ok(reply) => reply,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    _retries += 1;
                    self.send_raw(req1)?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            match reply.first().copied() {
                Some(0x06) => return Ok(reply),
                Some(0x01) => {
                    self.send_unconnected_pong(&reply)?;
                    if !answered_challenge {
                        answered_challenge = true;
                        self.send_raw(req1)?;
                    }
                }
                Some(0x19) => return Err(io::Error::new(io::ErrorKind::InvalidData, "ракнет версия не подходит")),
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("ожидал open1 ответ, а пришёл {}", packet_id_text(&reply)))),
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "нет open1 ответа"))
    }

    fn recv_open2_reply(&mut self, req2: &[u8]) -> io::Result<Vec<u8>> {
        let mut answered_challenge = false;
        let deadline = Instant::now() + Duration::from_secs(20);
        self.socket.set_read_timeout(Some(Duration::from_millis(1000)))?;
        let mut _retries = 0;
        while Instant::now() < deadline {
            let reply = match self.recv() {
                Ok(reply) => reply,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    _retries += 1;
                    self.send_raw(req2)?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let pkt_id = reply.first().copied().unwrap_or(0xff);
            rak(&format!("recv_open2_reply получаем пакет 0x{:02x}, {} байт", pkt_id, reply.len()));
            match reply.first().copied() {
                Some(0x08) => return Ok(reply),
                Some(0x06) => {
                    if reply.len() >= 28 {
                        self.srv_guid = read_i64_be(&reply, 17).unwrap_or(self.srv_guid);
                        self.mtu = u16::from_be_bytes([reply[26], reply[27]]);
                    }
                    self.send_raw(req2)?;
                }
                Some(0x01) => {
                    self.send_unconnected_pong(&reply)?;
                    if !answered_challenge {
                        answered_challenge = true;
                        self.send_raw(req2)?;
                    }
                }
                Some(id) => {
                    rak(&format!("в recv_open2_reply получаем неожиданный пакет 0x{:02x}", id));
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("ожидал open2 ответ, а пришел 0x{:02x}", id)));
                }
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "пустой пакет в recv_open2_reply")),
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "нет open2 ответа"))
    }

    fn send_unconnected_pong(&mut self, ping: &[u8]) -> io::Result<()> {
        let ping_time = read_i64_be(ping, 1).unwrap_or(0);
        let mut pong = Vec::new();
        pong.push(0x1c);
        put_i64_be(&mut pong, ping_time);
        put_i64_be(&mut pong, self.guid);
        pong.extend_from_slice(&MAGIC_BYTES);
        put_u16_be(&mut pong, 0);
        self.send_raw(&pong)?;
        Ok(())
    }

    pub fn handshake(&mut self) -> io::Result<()> {
        let request_time = self.elapsed_ms();
        let mut request = Vec::new();
        request.push(0x09);
        put_i64_be(&mut request, self.guid);
        put_i64_be(&mut request, request_time);
        request.push(0);
        self.send_rel(request)?;

        let accepted = self.wait_packet(0x10, Duration::from_secs(8))?;
        let server_time = read_i64_be(&accepted, accepted.len().saturating_sub(8)).unwrap_or(0);

        let mut incoming = Vec::new();
        incoming.push(0x13);
        put_addr(&mut incoming, &self.server);
        for _ in 0..20 {
            put_system_addr(&mut incoming, [255, 255, 255, 255], 0);
        }
        put_i64_be(&mut incoming, request_time);
        put_i64_be(&mut incoming, server_time);
        self.send_rel(incoming)?;

        let mut ping = vec![0x00];
        put_i64_be(&mut ping, self.elapsed_ms());
        self.send_unrel(ping)?;

        self.drain_initial_raknet(Duration::from_millis(700))?;
        Ok(())
    }

    fn drain_initial_raknet(&mut self, duration: Duration) -> io::Result<()> {
        self.socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            match self.recv() {
                Ok(buf) => self.on_packet(&buf)?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }
        self.socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        Ok(())
    }

    pub fn login(&mut self, login: Vec<u8>) -> io::Result<()> {
        net("шлём Login пакет");
        self.send(login, 3)
    }

    pub fn run(
        &mut self,
        timeout_secs: u64,
        chat_rx: Option<Receiver<String>>,
        interrupt_rx: Option<Receiver<()>>,
    ) -> io::Result<()> {
        self.socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let deadline = if timeout_secs == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(timeout_secs))
        };
        let mut last_ping = Instant::now();
        let _last_client_tick = Instant::now();

        loop {
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    break;
                }
            }
            if self.disconnected {
                break;
            }
            if INTERRUPTED.load(Ordering::SeqCst) {
                bot("завершено");
                break;
            }
            if let Some(chat_rx) = chat_rx.as_ref() {
                while let Ok(line) = chat_rx.try_recv() {
                    if line == "__EXIT__" {
                        bot("завершено");
                        self.disconnected = true;
                        break;
                    }
                    let message = line.trim();
                    if !message.is_empty() {
                        self.queue_console_message(message.to_string());
                    }
                }
            }
            if let Some(rx) = interrupt_rx.as_ref() {
                if rx.try_recv().is_ok() {
                    bot("завершено");
                    break;
                }
            }
            self.maybe_mark_spawned_fallback();
            self.resend()?;

            match event::poll(Duration::from_millis(0)) {
                Ok(true) => {
                    if let Event::Key(key) = event::read()? {
                        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                            bot("завершено");
                            break;
                        }
                    }
                }
                Ok(false) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }

            if last_ping.elapsed() >= Duration::from_secs(5) {
                let mut ping = vec![0x00];
                put_i64_be(&mut ping, self.elapsed_ms());
                self.send_unrel(ping)?;
                last_ping = Instant::now();
            }

            match self.recv() {
                Ok(buf) => self.on_packet(&buf)?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    if let Some(last) = self.last_recv_at {
                        if last.elapsed() >= Duration::from_secs(self.keepalive_timeout_secs) {
                            err(&format!("keepalive timeout: нет данных {} сек", self.keepalive_timeout_secs));
                            self.disconnected = true;
                        }
                    }
                }
                Err(e) => return Err(e),
            }
            self.maybe_mark_spawned_fallback();
            self.pump_pending_chat()?;
            if self.joined && self.movement_enabled {
                self.update_circular_movement()?;
            }
            if self.should_finish_after_scan() {
                break;
            }
        }
        bot(&format!("отключился, был в сети {} сек.", self.start.elapsed().as_secs()));
        Ok(())
    }

    pub fn disconnect(&mut self) -> io::Result<()> {
        if self.disconnected {
            return Ok(());
        }
        self.send_rel(vec![0x15])?;
        Ok(())
    }

    fn update_circular_movement(&mut self) -> io::Result<()> {
        let should_move = match self.last_movement_at {
            None => true,
            Some(last) => last.elapsed() >= Duration::from_millis(300),
        };
        if !should_move {
            return Ok(());
        }
        self.last_movement_at = Some(Instant::now());
        let radius = 2.5;
        let angle = (self.movement_phase as f32 * 0.1) % (2.0 * std::f32::consts::PI);
        let target_x = self.spawn_x + radius * angle.cos();
        let target_z = self.spawn_z + radius * angle.sin();
        let target_y = self.pos.1;
        let dx = target_x - self.pos.0;
        let dz = target_z - self.pos.2;
        let yaw = std::f32::consts::PI + dz.atan2(dx);

        let mut pkt = vec![0x13];
        pkt.extend_from_slice(&(self.entity_runtime_id as u64).to_le_bytes());
        pkt.push(0);
        pkt.extend_from_slice(&target_x.to_le_bytes());
        pkt.extend_from_slice(&target_y.to_le_bytes());
        pkt.extend_from_slice(&target_z.to_le_bytes());
        pkt.extend_from_slice(&self.pitch.to_le_bytes());
        pkt.extend_from_slice(&yaw.to_le_bytes());
        pkt.extend_from_slice(&yaw.to_le_bytes());
        pkt.push(0);
        pkt.push(1);
        pkt.extend_from_slice(&0u64.to_le_bytes());

        self.send_rel(pkt)?;
        self.movement_phase = self.movement_phase.wrapping_add(1);
        Ok(())
    }

    pub fn on_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        match buf[0] {
            0x80..=0x8f => {
                if let Some(seq) = read_triad_le(buf, 1) {
                    self.send_ack(seq)?;
                }
                let frames = parse_frames(&buf[4..]);
                for frame in frames {
                    if let Some(frame) = self.join_frame(frame) {
                        self.handle_inbound_frame(frame)?;
                    }
                }
            }
            0xc0 => self.handle_ack(buf),
            0xa0 => self.handle_nack(buf)?,
            id => { let _ = id; }
        }
        Ok(())
    }

    fn handle_ack(&mut self, buf: &[u8]) {
        for seq in parse_ack_records(buf) {
            self.pending.remove(&seq);
        }
    }

    fn clear_pending_after_progress(&mut self, _reason: &str) {
        if self.pending.is_empty() {
            return;
        }
        self.pending.clear();
    }

    fn handle_nack(&mut self, buf: &[u8]) -> io::Result<()> {
        for seq in parse_ack_records(buf) {
            if let Some(pending) = self.pending.remove(&seq) {
                if pending.sends < 5 {
                    self.resend_pending_datagram(seq, pending)?;
                }
            }
        }
        Ok(())
    }

    fn handle_inbound_frame(&mut self, frame: Frame) -> io::Result<()> {
        let Some(ord_idx) = frame.order_index else {
            return self.on_mcpe(&frame.payload);
        };
        let channel = frame.order_channel;
        let expected = *self.ord_idxs.entry(channel).or_insert(0);
        if ord_idx != expected {
            if ord_idx > expected {
                self.ord_frames.insert((channel, ord_idx), frame);
            }
            return Ok(());
        }
        self.consume_ordered_frame(frame)?;
        while let Some(next) = self.ord_frames.remove(&(channel, *self.ord_idxs.entry(channel).or_insert(0))) {
            self.consume_ordered_frame(next)?;
        }
        Ok(())
    }

    fn consume_ordered_frame(&mut self, frame: Frame) -> io::Result<()> {
        self.mark_order_consumed(&frame);
        self.on_mcpe(&frame.payload)
    }

    fn mark_order_consumed(&mut self, frame: &Frame) {
        let Some(ord_idx) = frame.order_index else { return };
        let expected = self.ord_idxs.entry(frame.order_channel).or_insert(0);
        if ord_idx >= *expected {
            *expected = ord_idx.wrapping_add(1);
        }
    }

    fn on_mcpe(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        self.dump_mcpe("in", payload)?;

        match payload[0] {
            0x00 => {
                let client_time = read_i64_be(payload, 1).unwrap_or(0);
                let mut pong = vec![0x03];
                put_i64_be(&mut pong, client_time);
                put_i64_be(&mut pong, self.elapsed_ms());
                self.send_unrel(pong)?;
            }
            0x03 => self.on_handshake(payload)?,
            0x8f => net("получаем NetworkSettings, отправляем Login"),
            0xfe => self.on_batch(&payload[1..])?,
            0x02 => self.on_status(payload)?,
            0x0b => {
                self.clear_pending_after_progress("StartGame");
                self.status_text = "подключен".to_string();
                self.push_event("бот вошел на сервер");
                self.saw_start_game = true;
                self.joined = true;
                self.read_start_game(payload);
                if !self.sent_chunk_radius {
                    self.sent_chunk_radius = true;
                    self.send_request_chunk_radius(self.chunk_radius)?
                }
            }
            0x05 => {
                let reason = describe_disconnect(payload);
                self.status_text = "отключен".to_string();
                self.push_event(format!("[отключение] {reason}"));
                self.disconnected = true;
            }
            0x06 => self.on_packs(payload)?,
            0x07 => {
                let ids = self.pack_ids.clone();
                self.send_resource_pack_response(4, &ids)?;
                if !self.sent_chunk_radius {
                    self.sent_chunk_radius = true;
                    self.send_request_chunk_radius(self.chunk_radius)?;
                }
            }
            0x09 => self.on_text(payload),
            0x59 => self.on_title(payload),
            0x53 => self.on_pack_info(payload)?,
            0x54 => self.on_pack_chunk(payload)?,
            _ => self.log_in_quiet_packet(payload)?,
        }
        Ok(())
    }

    fn on_batch(&mut self, data: &[u8]) -> io::Result<()> {
        let decrypted;
        let data = if let Some(enc) = self.enc.as_mut() {
            match enc.decrypt(data) {
                Ok(value) => {
                    self.bad_enc = 0;
                    decrypted = value;
                    decrypted.as_slice()
                }
                Err(_) => {
                    self.bad_enc = self.bad_enc.saturating_add(1);
                    return Ok(());
                }
            }
        } else {
            data
        };

        let mut decoder = ZlibDecoder::new(data);
        let mut decoded = Vec::new();
        if let Err(err) = decoder.read_to_end(&mut decoded) {
            self.bad_batch = self.bad_batch.saturating_add(1);
            let _ = err;
            return Ok(());
        }

        let mut offset = 0;
        while offset < decoded.len() {
            let Some(packet_len) = read_var_u32(&decoded, &mut offset) else { break };
            let packet_len = packet_len as usize;
            if offset + packet_len > decoded.len() { break; }
            self.on_mcpe(&decoded[offset..offset + packet_len])?;
            offset += packet_len;
        }
        Ok(())
    }

    fn on_status(&mut self, payload: &[u8]) -> io::Result<()> {
        if let Some(status) = read_u32_be(payload, 1) {
            if matches!(status, 0 | 3) {
                self.clear_pending_after_progress("PlayStatus");
            }
            let text = match status {
                0 => "вход успешен",
                1 => "старый клиент",
                2 => "старый сервер",
                3 => "в игре",
                4 => "аккаунт недопустим",
                5 => "версия не та",
                6 => "версия не та",
                _ => "неизвестно",
            };
            if status == 3 {
                self.joined = true;
                self.status_text = "в игре".to_string();
                self.push_event("бот вошёл в игру");
            } else {
                self.status_text = text.to_string();
                self.push_event(format!("[статус] {text}"));
            }
        }
        Ok(())
    }

    fn on_handshake(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut offset = 1;
        let Some(public_key) = read_mcpe_string(payload, &mut offset) else { return Ok(()) };
        let Some(server_token) = read_mcpe_string(payload, &mut offset) else { return Ok(()) };
        if public_key.is_empty() || server_token.is_empty() { return Ok(()) }

        if !self.sent_client_handshake {
            let key = self.auth.derive_encryption_key(&public_key, &server_token)?;
            self.enc = Some(EncryptionState::new(key)?);
            cry("шифрование включено");
            self.sent_client_handshake = true;
            self.send_client_handshake()?;
        }
        Ok(())
    }

    fn on_text(&mut self, payload: &[u8]) {
        self.bump_in_packet(0x09);
        let mut offset = 1;
        let Some(text_type) = payload.get(offset).copied() else { return };
        offset += 1;
        if text_type == 4 { return; }

        match text_type {
            0 | 5 => {
                if let Some(message) = read_mcpe_utf8_string(payload, &mut offset) {
                    self.note_server_text(&message);
                    self.log_text_line(format!("[{}] {}", text_type_name(text_type), message));
                }
            }
            1 | 3 | 6 => {
                let source = read_mcpe_utf8_string(payload, &mut offset).unwrap_or_default();
                let message = read_mcpe_utf8_string(payload, &mut offset).unwrap_or_default();
                self.note_server_text(&source);
                self.note_server_text(&message);
                if text_type == 3 && message.trim().is_empty() {
                    self.log_text_line(format!("[popup] {}", source));
                } else if source.is_empty() {
                    self.log_text_line(format!("[{}] {}", text_type_name(text_type), message));
                } else {
                    self.log_text_line(format!("[{}] <{}> {}", text_type_name(text_type), source, message));
                }
            }
            2 => {
                let message = read_mcpe_utf8_string(payload, &mut offset).unwrap_or_default();
                self.note_server_text(&message);
                let count = read_var_u32(payload, &mut offset).unwrap_or(0);
                let mut params = Vec::new();
                for _ in 0..count {
                    if let Some(param) = read_mcpe_utf8_string(payload, &mut offset) {
                        self.note_server_text(&param);
                        params.push(param);
                    }
                }
                if params.is_empty() {
                    self.log_text_line(format!("[translation] {}", message));
                } else {
                    self.log_text_line(format!("[translation] {} | {}", message, params.join(", ")));
                }
            }
            _ => {}
        }
    }

    fn on_title(&mut self, payload: &[u8]) {
        self.bump_in_packet(0x59);
        let mut offset = 1;
        let Some(title_type) = read_var_u32(payload, &mut offset) else { return };
        if matches!(title_type, 0 | 1 | 4 | 5) { return; }
        let title = read_mcpe_utf8_string(payload, &mut offset).unwrap_or_default();
        let _fade_in = read_var_u32(payload, &mut offset).unwrap_or(0);
        let _duration = read_var_u32(payload, &mut offset).unwrap_or(0);
        let _fade_out = read_var_u32(payload, &mut offset).unwrap_or(0);
        if title.trim().is_empty() { return; }
        self.log_text_line(format!("[{}] {}", set_title_type_name(title_type), title));
    }

    fn on_packs(&mut self, payload: &[u8]) -> io::Result<()> {
        let Some(info) = parse_resource_packs_info(payload) else {
            return self.send_resource_pack_response(3, &[]);
        };
        let mut entries = Vec::new();
        entries.extend(info.behavior);
        entries.extend(info.resources);
        self.pack_ids = entries.iter().map(|entry| entry.id.clone()).collect();
        self.packs.clear();
        self.sent_have_all_packs = false;

        if entries.is_empty() {
            self.sent_have_all_packs = true;
            return self.send_resource_pack_response(3, &[]);
        }
        let ids: Vec<String> = entries.into_iter().map(|entry| entry.id).collect();
        self.send_resource_pack_response(2, &ids)
    }

    fn on_pack_info(&mut self, payload: &[u8]) -> io::Result<()> {
        let Some(info) = parse_resource_pack_data_info(payload) else { return Ok(()) };
        let chunk_count = info.chunk_count as usize;
        self.packs.insert(info.id.clone(), PackDl {
            max_chunk_size: info.max_chunk_size,
            chunk_count: info.chunk_count,
            compressed_size: info.compressed_size,
            received_count: 0,
            next_request: 0,
            in_flight: 0,
            chunks: vec![None; chunk_count],
            saved: false,
        });
        self.request_more_pack_chunks(&info.id)?;
        self.maybe_send_have_all_packs()
    }

    fn on_pack_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let Some(chunk) = parse_resource_pack_chunk_data(payload) else { return Ok(()) };
        let mut complete = false;
        if let Some(download) = self.packs.get_mut(&chunk.id) {
            if download.in_flight > 0 { download.in_flight -= 1; }
            let index = chunk.index as usize;
            if index < download.chunks.len() && download.chunks[index].is_none() {
                download.chunks[index] = Some(chunk.data);
                download.received_count = download.received_count.saturating_add(1);
            }
            complete = download.complete();
        }
        if complete {
            self.save_completed_resource_pack(&chunk.id)?;
        }
        self.request_more_pack_chunks(&chunk.id)?;
        self.maybe_send_have_all_packs()
    }

    fn request_more_pack_chunks(&mut self, pack_id: &str) -> io::Result<()> {
        let mut requests = Vec::new();
        if let Some(download) = self.packs.get_mut(pack_id) {
            while download.in_flight < 4 && download.next_request < download.chunk_count {
                let index = download.next_request;
                download.next_request += 1;
                download.in_flight += 1;
                requests.push(index);
            }
        }
        for index in requests {
            self.send_resource_pack_chunk_request(pack_id, index)?;
        }
        Ok(())
    }

    fn save_completed_resource_pack(&mut self, pack_id: &str) -> io::Result<()> {
        let Some(download) = self.packs.get_mut(pack_id) else { return Ok(()) };
        if download.saved || !download.complete() { return Ok(()) }
        let mut data = Vec::new();
        for chunk in &download.chunks {
            if let Some(chunk) = chunk { data.extend_from_slice(chunk); }
        }
        download.saved = true;
        let folder = format!("target/resource_packs/{}", sanitize_dump_part(pack_id));
        fs::create_dir_all(&folder)?;

        let mut unpacked = Vec::new();
        let is_zlib_ok = ZlibDecoder::new(&data[..]).read_to_end(&mut unpacked).is_ok();
        let to_save = if is_zlib_ok && !unpacked.is_empty() { unpacked } else { data };

        fs::write(format!("{}/pack.bin", folder), &to_save)?;
        Ok(())
    }

    fn maybe_send_have_all_packs(&mut self) -> io::Result<()> {
        if self.sent_have_all_packs || self.pack_ids.is_empty() { return Ok(()) }
        let all_done = self.pack_ids.iter().all(|id| {
            self.packs.get(id).is_some_and(PackDl::complete)
        });
        if all_done {
            self.sent_have_all_packs = true;
            let ids = self.pack_ids.clone();
            self.send_resource_pack_response(3, &ids)?;
        }
        Ok(())
    }

    fn log_text_line(&mut self, line: String) {
        let line = clean_console_line(&line);
        if line.is_empty() { return; }
        let count = self.text_line_counts.entry(line.clone()).or_insert(0);
        *count = count.saturating_add(1);
        self.last_text_line = line.clone();
        if self.show_output.load(Ordering::Relaxed) {
            let colored = mc_to_ansi(&line);
            println!("{colored}");
            io::stdout().flush().ok();
        }
    }

    fn log_in_quiet_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        let id = payload.first().copied().unwrap_or(0xff);
        let _count = self.bump_in_packet(id);
        match id {
            0x3a => {
                self.last_chunk_at = Some(Instant::now());
                if self.saw_start_game && self.first_chunk_at.is_none() {
                    self.first_chunk_at = Some(Instant::now());
                }
                self.save_level_chunk(payload)?
            }
            0x46 => {
                let mut offset = 1;
                if let Some(radius) = read_var_u32(payload, &mut offset) {
                    self.chunk_radius = radius;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn note_server_text(&mut self, text: &str) {
        let lower = text.to_lowercase();
        let auth_success = lower.contains("успешно") || lower.contains("теперь твой ник")
            || lower.contains("вы вошли") || lower.contains("ты вошел")
            || lower.contains("logged in") || lower.contains("registered");
        if auth_success {
            self.last_auth_transition_at = Some(Instant::now());
        }
    }

    fn queue_console_message(&mut self, message: String) {
        self.pending_chat.push_back(message);
    }

    pub fn push_event(&mut self, line: impl Into<String>) {
        let line = clean_console_line(&line.into());
        if line.is_empty() { return; }
        if self.show_output.load(Ordering::Relaxed) {
            println!("{line}");
            io::stdout().flush().ok();
        }
        self.event_log.push_back(trim_for_log(&line, 220));
        while self.event_log.len() > 12 {
            self.event_log.pop_front();
        }
    }

    pub fn saved_chunk_count(&self) -> usize { 0 }
    pub fn bad_chunk_count(&self) -> u32 { 0 }

    fn save_level_chunk(&mut self, _payload: &[u8]) -> io::Result<()> { Ok(()) }

    fn should_finish_after_scan(&self) -> bool {
        if !self.finish_after_scan { return false; }
        let Some(scan_complete_at) = self.scan_complete_at else { return false; };
        let idle = Duration::from_millis(self.scan_idle_finish_ms);
        if scan_complete_at.elapsed() < idle { return false; }
        self.last_chunk_at.map(|last| last.elapsed() >= idle).unwrap_or(true)
    }

    pub fn finish_world_export(&mut self) -> io::Result<()> { Ok(()) }

    fn maybe_mark_spawned_fallback(&mut self) {
        if self.joined || !self.saw_start_game { return; }
        let Some(first_chunk_at) = self.first_chunk_at else { return; };
        let chunk_count = self.in_cnt.get(&0x3a).copied().unwrap_or(0);
        let required_chunks = estimated_spawn_chunks(self.chunk_radius);
        if chunk_count >= required_chunks || first_chunk_at.elapsed() >= Duration::from_millis(self.spawn_fallback_ms) {
            self.joined = true;
            self.status_text = "в игре".to_string();
        }
    }

    fn log_out_packet(&mut self, payload: &[u8]) {
        let id = payload.first().copied().unwrap_or(0xff);
        self.bump_out_packet(id);
    }

    fn bump_in_packet(&mut self, id: u8) -> u32 {
        let count = self.in_cnt.entry(id).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    fn bump_out_packet(&mut self, id: u8) -> u32 {
        let count = self.out_cnt.entry(id).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    fn send_mcpe_packet(&mut self, packet: Vec<u8>) -> io::Result<()> {
        self.send(packet, 3)
    }

    fn send(&mut self, packet: Vec<u8>, reliability: u8) -> io::Result<()> {
        self.log_out_packet(&packet);
        self.dump_mcpe("out", &packet)?;
        self.send_batch_with_reliability(vec![packet], reliability)
    }

    fn send_mcpe_raw_packet_with_reliability(&mut self, packet: Vec<u8>, reliability: u8) -> io::Result<()> {
        if self.enc.is_some() {
            return self.send(packet, reliability);
        }
        self.log_out_packet(&packet);
        self.dump_mcpe("out", &packet)?;
        self.send_frame(packet, reliability)
    }

    fn send_resource_pack_response(&mut self, status: u8, pack_ids: &[String]) -> io::Result<()> {
        let mut pk = vec![0x08, status];
        put_u16_le(&mut pk, pack_ids.len() as u16);
        for id in pack_ids { put_mcpe_string(&mut pk, id.as_bytes()); }
        self.send_mcpe_packet(pk)
    }

    fn send_resource_pack_chunk_request(&mut self, pack_id: &str, chunk_index: u32) -> io::Result<()> {
        let mut pk = vec![0x55];
        put_mcpe_string(&mut pk, pack_id.as_bytes());
        put_u32_le(&mut pk, chunk_index);
        self.send_mcpe_packet(pk)
    }

    fn send_console_message(&mut self, message: &str) -> io::Result<()> {
        if self.command_step_for_slash && message.trim_start().starts_with('/') {
            self.send_command_step(message)
        } else {
            self.send_chat_message(message)
        }
    }

    fn send_command_step(&mut self, message: &str) -> io::Result<()> {
        let command_line = message.trim_start().trim_start_matches('/').trim();
        if command_line.is_empty() { return self.send_chat_message(message); }
        let (command, input_json) = command_step_payload(command_line, self.command_step_split_args);

        let mut pk = vec![0x4f];
        put_mcpe_string(&mut pk, command.as_bytes());
        put_mcpe_string(&mut pk, b"");
        put_var_u32(&mut pk, 0);
        put_var_u32(&mut pk, 0);
        pk.push(1);
        put_var_u64(&mut pk, (self.guid as u64) & 0x7fff_ffff);
        put_mcpe_string(&mut pk, input_json.as_bytes());
        put_mcpe_string(&mut pk, b"");
        self.send(pk, self.chat_reliability)
    }

    fn send_chat_message(&mut self, message: &str) -> io::Result<()> {
        let mut pk = vec![0x09];
        if self.chat_raw {
            pk.push(0);
        } else if self.chat_no_source {
            pk.push(1);
        } else {
            pk.push(1);
            if self.chat_source_name {
                let source = self.name.clone();
                put_mcpe_string(&mut pk, source.as_bytes());
            } else {
                put_mcpe_string(&mut pk, b"");
            }
        }
        put_mcpe_string(&mut pk, message.as_bytes());
        self.send(pk, self.chat_reliability)
    }

    fn pump_pending_chat(&mut self) -> io::Result<()> {
        if !self.joined || self.pending_chat.is_empty() { return Ok(()); }
        if let Some(last_sent) = self.last_chat_sent_at {
            if last_sent.elapsed() < Duration::from_millis(self.chat_interval_ms) { return Ok(()); }
        }
        if let Some(last_chunk) = self.last_chunk_at {
            if last_chunk.elapsed() < Duration::from_millis(self.chat_quiet_ms) { return Ok(()); }
        }
        if let Some(last_auth) = self.last_auth_transition_at {
            if last_auth.elapsed() < Duration::from_millis(self.post_auth_delay_ms) { return Ok(()); }
        }
        if self.pending.len() > 16 {
            return Ok(());
        }
        if let Some(message) = self.pending_chat.pop_front() {
            self.send_console_message(&message)?;
            self.last_chat_sent_at = Some(Instant::now());
            self.last_chat_wait_log_at = None;
        }
        Ok(())
    }

    fn send_client_handshake(&mut self) -> io::Result<()> {
        self.send_mcpe_packet(vec![0x04])
    }

    fn send_batch_with_reliability(&mut self, packets: Vec<Vec<u8>>, reliability: u8) -> io::Result<()> {
        let mut raw = Vec::new();
        for packet in packets {
            put_var_u32(&mut raw, packet.len() as u32);
            raw.extend_from_slice(&packet);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&raw)?;
        let mut compressed = encoder.finish()?;
        if let Some(enc) = self.enc.as_mut() {
            compressed = enc.encrypt(compressed);
        }
        let mut batch = vec![0xfe];
        batch.extend_from_slice(&compressed);
        self.send_frame(batch, reliability)
    }

    fn send_request_chunk_radius(&mut self, radius: u32) -> io::Result<()> {
        let mut pk = vec![0x45];
        put_var_u32(&mut pk, radius);
        self.send_mcpe_packet(pk)
    }

    fn dump_mcpe(&mut self, dir: &str, payload: &[u8]) -> io::Result<()> {
        if !self.dump_enabled { return Ok(()); }
        let id = payload.first().copied().unwrap_or(0xff);
        let name = packet_name(id);
        writeln!(self.dump, "{:>8}ms {dir:<3} 0x{id:02x} {name:<32} len={} {}", self.elapsed_ms(), payload.len(), describe_bytes(payload))
    }

    fn send_rel(&mut self, payload: Vec<u8>) -> io::Result<()> {
        self.send_frame(payload, 3)
    }

    fn send_unrel(&mut self, payload: Vec<u8>) -> io::Result<()> {
        self.send_frame(payload, 0)
    }

    fn send_frame(&mut self, payload: Vec<u8>, reliability: u8) -> io::Result<()> {
        let max_payload = self.max_frame_payload(reliability, false);
        if payload.len() > max_payload && max_payload > 0 {
            return self.send_split_frame(payload, reliability, self.max_frame_payload(reliability, true));
        }

        let mut datagram = Vec::new();
        datagram.push(0x80);
        put_triad_le(&mut datagram, self.seq);
        self.seq = self.seq.wrapping_add(1);

        datagram.push(reliability << 5);
        put_u16_be(&mut datagram, (payload.len() * 8) as u16);
        if reliability == 2 || reliability == 3 || reliability == 4 {
            put_triad_le(&mut datagram, self.rel_idx);
            self.rel_idx = self.rel_idx.wrapping_add(1);
        }
        if reliability == 1 || reliability == 3 || reliability == 4 {
            put_triad_le(&mut datagram, self.ord_idx);
            self.ord_idx = self.ord_idx.wrapping_add(1);
            datagram.push(0);
        }
        datagram.extend_from_slice(&payload);
        self.track_reliable_datagram(&datagram, reliability);
        self.send_raw(&datagram)?;
        Ok(())
    }

    fn send_split_frame(&mut self, payload: Vec<u8>, reliability: u8, max_payload: usize) -> io::Result<()> {
        let split_id = self.split_id;
        self.split_id = self.split_id.wrapping_add(1);
        if self.split_id == 0 { self.split_id = 1; }
        let chunks: Vec<&[u8]> = payload.chunks(max_payload).collect();
        let count = chunks.len() as u32;
        let _ = (payload.len(), count, max_payload, split_id);

        let base_ord = self.ord_idx;

        for (index, chunk) in chunks.into_iter().enumerate() {
            let mut datagram = Vec::new();
            datagram.push(0x80);
            put_triad_le(&mut datagram, self.seq);
            self.seq = self.seq.wrapping_add(1);

            datagram.push((reliability << 5) | 0x10);
            put_u16_be(&mut datagram, (chunk.len() * 8) as u16);
            if reliability == 2 || reliability == 3 || reliability == 4 {
                put_triad_le(&mut datagram, self.rel_idx);
                self.rel_idx = self.rel_idx.wrapping_add(1);
            }
            if reliability == 1 || reliability == 3 || reliability == 4 {
                put_triad_le(&mut datagram, base_ord);
                datagram.push(0);
            }
            put_u32_be(&mut datagram, count);
            put_u16_be(&mut datagram, split_id);
            put_u32_be(&mut datagram, index as u32);
            datagram.extend_from_slice(chunk);
            self.track_reliable_datagram(&datagram, reliability);
            self.send_raw(&datagram)?;
        }

        if reliability == 1 || reliability == 3 || reliability == 4 {
            self.ord_idx = self.ord_idx.wrapping_add(1);
        }
        Ok(())
    }

    fn track_reliable_datagram(&mut self, datagram: &[u8], reliability: u8) {
        if !(reliability == 2 || reliability == 3 || reliability == 4) { return; }
        let Some(seq) = read_triad_le(datagram, 1) else { return; };
        self.pending.insert(seq, PendingDatagram {
            frame_bytes: datagram[4..].to_vec(),
            last_sent: Instant::now(),
            sends: 1,
        });
    }

    fn resend(&mut self) -> io::Result<()> {
        let now = Instant::now();
        let stale: Vec<u32> = self.pending.iter()
            .filter_map(|(seq, pending)| {
                let age = now.duration_since(pending.last_sent);
                if pending.sends >= 5 || age >= Duration::from_secs(5) {
                    Some(*seq)
                } else if age >= Duration::from_millis(800) {
                    Some(*seq)
                } else {
                    None
                }
            })
            .collect();
        for seq in stale {
            if let Some(pending) = self.pending.remove(&seq) {
                if pending.sends < 5 {
                    let _ = self.resend_pending_datagram(seq, pending);
                }
            }
        }
        Ok(())
    }

    fn resend_pending_datagram(&mut self, old_seq: u32, mut pending: PendingDatagram) -> io::Result<()> {
        let new_seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let mut datagram = Vec::with_capacity(4 + pending.frame_bytes.len());
        datagram.push(0x80);
        put_triad_le(&mut datagram, new_seq);
        datagram.extend_from_slice(&pending.frame_bytes);
        pending.sends = pending.sends.saturating_add(1);
        pending.last_sent = Instant::now();
        self.pending.insert(new_seq, pending);
        self.log_reliable_resend(old_seq, new_seq);
        self.send_raw(&datagram)
    }

    fn log_reliable_resend(&mut self, _old_seq: u32, _new_seq: u32) {
        self.resend_log_count = self.resend_log_count.saturating_add(1);
    }

    fn max_frame_payload(&self, reliability: u8, split: bool) -> usize {
        let max_datagram_payload = self.mtu.saturating_sub(40) as usize;
        let limit = max_datagram_payload.saturating_sub(frame_header_len(reliability, split));
        if split {
            if let Some(chunk) = self.split_chunk {
                return limit.min(chunk.max(1));
            }
        }
        limit
    }

    fn send_ack(&mut self, seq: u32) -> io::Result<()> {
        let mut ack = Vec::new();
        ack.push(0xc0);
        put_u16_be(&mut ack, 1);
        ack.push(0);
        put_triad_le(&mut ack, seq);
        put_triad_le(&mut ack, seq);
        self.send_raw(&ack)?;
        Ok(())
    }

    fn wait_packet(&mut self, id: u8, timeout: Duration) -> io::Result<Vec<u8>> {
        self.socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            self.resend()?;
            let buf = match self.recv() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => {
                    self.socket.set_read_timeout(Some(Duration::from_secs(10)))?;
                    return Err(e);
                }
            };
            if !matches!(buf.first().copied(), Some(0x80..=0x8f)) { continue; }
            if let Some(seq) = read_triad_le(&buf, 1) { self.send_ack(seq)?; }
            for frame in parse_frames(&buf[4..]) {
                let Some(frame) = self.join_frame(frame) else { continue; };
                let pk_id = frame.payload.first().copied().unwrap_or(0xff);
                if pk_id != 0x00 && pk_id != 0x03 {
                    net(&format!("получаем пакет 0x{:02x} {}", pk_id, packet_name(pk_id)));
                }
                if pk_id == id {
                    self.mark_order_consumed(&frame);
                    self.socket.set_read_timeout(Some(Duration::from_secs(10)))?;
                    return Ok(frame.payload);
                }
                self.handle_inbound_frame(frame)?;
            }
        }
        self.socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        Err(io::Error::new(io::ErrorKind::TimedOut, format!("не дождался пакета 0x{id:02x}")))
    }

    fn send_raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.dump_raw_udp("out", data)?;
        loop {
            match self.socket.send_to(data, self.server) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 4096];
        let (len, from) = loop {
            match self.socket.recv_from(&mut buf) {
                Ok(result) => break result,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        };
        buf.truncate(len);
        self.last_recv_at = Some(Instant::now());
        if from.ip() != self.server.ip() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("пришел пакет с левого адреса {from}")));
        }
        self.dump_raw_udp("in", &buf)?;
        Ok(buf)
    }

    fn dump_raw_udp(&mut self, dir: &str, payload: &[u8]) -> io::Result<()> {
        if !self.dump_enabled { return Ok(()); }
        let id = payload.first().copied().unwrap_or(0xff);
        writeln!(self.raw_dump, "{:>8}ms {dir:<3} 0x{id:02x} {name:<28} len={} {}", self.elapsed_ms(), payload.len(), describe_bytes(payload), name = raknet_packet_name(id))
    }

    fn elapsed_ms(&self) -> i64 {
        self.start.elapsed().as_millis() as i64
    }

    fn read_start_game(&mut self, payload: &[u8]) {
        let mut offset = 1;
        let _unique_id = read_var_u32(payload, &mut offset);
        if let Some(runtime_id) = read_var_u32(payload, &mut offset) {
            self.entity_runtime_id = runtime_id as i32;
        }
        let _gamemode = read_var_u32(payload, &mut offset);
        let Some(x) = read_f32_le(payload, offset) else { return; };
        offset += 4;
        let Some(y) = read_f32_le(payload, offset) else { return; };
        offset += 4;
        let Some(z) = read_f32_le(payload, offset) else { return; };
        offset += 4;
        let Some(pitch) = read_f32_le(payload, offset) else { return; };
        offset += 4;
        let Some(yaw) = read_f32_le(payload, offset) else { return; };
        self.pos = (x, y, z);
        self.pitch = pitch;
        self.yaw = yaw;

        self.spawn_x = x;
        self.spawn_z = z;

        self.status_text = "в игре".to_string();
        self.push_event(format!("спавн: x={:.1} y={:.1} z={:.1}", x, y, z));
    }

    fn join_frame(&mut self, mut frame: Frame) -> Option<Frame> {
        let Some(split) = frame.split else { return Some(frame); };

        if self.splits.len() > 20 {
            self.splits.clear();
        }

        let buffer = self.splits.entry(split.id).or_insert_with(|| SplitBuffer { parts: vec![None; split.count as usize] });
        if split.index as usize >= buffer.parts.len() { return None; }
        buffer.parts[split.index as usize] = Some(std::mem::take(&mut frame.payload));
        if buffer.parts.iter().all(Option::is_some) {
            let buffer = self.splits.remove(&split.id)?;
            let mut joined = Vec::new();
            for part in buffer.parts { joined.extend_from_slice(&part?); }
            frame.payload = joined;
            frame.split = None;
            return Some(frame);
        }
        None
    }
}