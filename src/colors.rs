pub fn mc_to_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '§' {
            if let Some(&code) = chars.peek() {
                chars.next();
                let ansi = match code.to_ascii_lowercase() {
                    '0' => "\x1b[30m",
                    '1' => "\x1b[34m",
                    '2' => "\x1b[32m",
                    '3' => "\x1b[36m",
                    '4' => "\x1b[31m",
                    '5' => "\x1b[35m",
                    '6' => "\x1b[33m",
                    '7' => "\x1b[37m",
                    '8' => "\x1b[90m",
                    '9' => "\x1b[94m",
                    'a' => "\x1b[92m",
                    'b' => "\x1b[96m",
                    'c' => "\x1b[91m",
                    'd' => "\x1b[95m",
                    'e' => "\x1b[93m",
                    'f' => "\x1b[97m",
                    'l' => "\x1b[1m",
                    'o' => "\x1b[3m",
                    'n' => "\x1b[4m",
                    'm' => "\x1b[9m",
                    'k' => "\x1b[5m",
                    'r' => "\x1b[0m",
                    _ => "",
                };
                out.push_str(ansi);
            }
        } else {
            out.push(ch);
        }
    }
    out.push_str("\x1b[0m");
    out
}
