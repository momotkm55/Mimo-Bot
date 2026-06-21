pub fn srv(msg: &str) { print!("\x1b[94m[\x1b[92mсерв\x1b[94m] \x1b[0m{}\n", msg); }
pub fn bot(msg: &str) { print!("\x1b[94m[\x1b[96mбот\x1b[94m] \x1b[0m{}\n", msg); }
pub fn rak(msg: &str) { print!("\x1b[94m[\x1b[93mракнет\x1b[94m] \x1b[0m{}\n", msg); }
pub fn net(msg: &str) { print!("\x1b[94m[\x1b[95mсеть\x1b[94m] \x1b[0m{}\n", msg); }
pub fn cry(msg: &str) { print!("\x1b[94m[\x1b[96mкрипт\x1b[94m] \x1b[0m{}\n", msg); }
pub fn err(msg: &str) { print!("\x1b[91m[ошибка] \x1b[0m{}\n", msg); }

pub fn banner() {
    print!("\x1b[96m");
    println!("  ██████╗ █████╗ ██╗     ██╗   ██╗██╗   ██╗███╗   ██╗");
    println!("  ██╔════╝██╔══██╗██║     ██║   ██║╚██╗ ██╔╝████╗  ██║");
    println!("  ██║     ███████║██║     ██║   ██║ ╚████╔╝ ██╔██╗ ██║");
    println!("  ██║     ██╔══██║██║     ╚██╗ ██╔╝  ╚██╔╝  ██║╚██╗██║");
    println!("  ╚██████╗██║  ██║███████╗ ╚████╔╝    ██║   ██║ ╚████║");
    println!("   ╚═════╝╚═╝  ╚═╝╚══════╝  ╚═══╝     ╚═╝   ╚═╝  ╚═══╝");
    println!("");
    println!("   ██████╗  ██████╗ ████████╗");
    println!("   ██╔══██╗██╔═══██╗╚══██╔══╝");
    println!("   ██████╔╝██║   ██║   ██║");
    println!("   ██╔══██╗██║   ██║   ██║");
    println!("   ██████╔╝╚██████╔╝   ██║");
    println!("   ╚═════╝  ╚═════╝    ╚═╝");
    print!("\x1b[0m\n");
}
pub fn start(host: &str, port: u16, name: &str) { print!("\x1b[90m[старт] \x1b[0m→ {}:{} игрок={}\n", host, port, name); }
pub fn motd(m: &str) { srv(m); }
pub fn mtu(mtu: u16, ver: u8) { rak(&format!("пробуем mtu={} ver={}", mtu, ver)); }
pub fn open1() { rak("получаем OpenConnectionReply1"); }
pub fn open1_done(mtu: u16) { rak(&format!("соединение установили, mtu {}", mtu)); }
pub fn open2_send() { rak("отправка OpenConnectionRequest2"); }
pub fn open2_recv() { rak("получаем OpenConnectionReply2"); }
pub fn open2_err(e: &str) { err(e); }
pub fn login_send() { net("отправка Login пакета"); }
pub fn net_settings() { net("получаем NetworkSettings, отправляем Login"); }
pub fn enc_on() { cry("шифрование включено"); }
pub fn ctrl_c() { bot("завершение"); }
pub fn cmd_exit() { bot("завершение"); }
pub fn connected(sec: u64) { bot(&format!("отключился, был в сети {} сек", sec)); }
pub fn pkt(id: u8, name: &str) { net(&format!("получаем пакет 0x{:02x} {}", id, name)); }
pub fn user(line: &str) { print!("\x1b[92m[я] \x1b[0m{}\n", line); }