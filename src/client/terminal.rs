use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::terminal::{self, ClearType};
use crossterm::{execute, queue};
use std::io::{self, Write};
use std::time::Instant;

pub struct TerminalCursorGuard;

impl TerminalCursorGuard {
    pub fn hide<W: Write>(out: &mut W) -> io::Result<Self> {
        write!(out, "\x1b[?25l")?;
        Ok(Self)
    }
}

impl Drop for TerminalCursorGuard {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = write!(out, "\x1b[?25h");
        let _ = out.flush();
    }
}

pub struct LiveTerminal {
    pub input: String,
    pub frame: usize,
    pub last_render: Instant,
}

pub enum UiAction {
    None,
    Submit(String),
    Quit,
}

impl LiveTerminal {
    pub fn new() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut out = io::stdout();
        execute!(
            out,
            terminal::EnterAlternateScreen,
            cursor::Hide,
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0)
        )?;
        Ok(Self {
            input: String::new(),
            frame: 0,
            last_render: Instant::now() - Duration::from_secs(1),
        })
    }

    pub fn poll_input(&mut self) -> io::Result<UiAction> {
        while event::poll(Duration::from_millis(0))? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(UiAction::Quit);
                }
                KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(UiAction::Quit);
                }
                KeyCode::Esc => self.input.clear(),
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::Enter => {
                    let line = self.input.trim().to_string();
                    self.input.clear();
                    if !line.is_empty() {
                        return Ok(UiAction::Submit(line));
                    }
                }
                KeyCode::Char(ch) => {
                    if !key.modifiers.contains(KeyModifiers::CONTROL) {
                        self.input.push(ch);
                    }
                }
                _ => {}
            }
        }
        Ok(UiAction::None)
    }

    pub fn render(&mut self, client: &super::Client, deadline: Option<Instant>) -> io::Result<()> {
        if self.last_render.elapsed() < Duration::from_millis(90) {
            return Ok(());
        }
        self.last_render = Instant::now();
        self.frame = self.frame.wrapping_add(1);

        let (width, _height) = terminal::size().unwrap_or((100, 30));
        let width = width.max(60) as usize;
        let inner = width.saturating_sub(4);
        let mut out = io::stdout();
        queue!(out, cursor::MoveTo(0, 0))?;

        draw_line(
            &mut out,
            Color::DarkCyan,
            &format!("+{}+", "-".repeat(width - 2)),
        )?;

        let elapsed = client.start.elapsed().as_secs();
        let mins = elapsed / 60;
        let secs = elapsed % 60;
        let pos = client.pos;
        let cx = (pos.0.floor() as i32).div_euclid(16);
        let cz = (pos.2.floor() as i32).div_euclid(16);

        draw_padded(
            &mut out,
            Color::Cyan,
            width,
            &format!("бот {} | имя {} | время {}м{}с | сервер {}", spinner(self.frame), client.name, mins, secs, client.server),
        )?;

        draw_line(
            &mut out,
            Color::DarkCyan,
            &format!("+{}+", "-".repeat(width - 2)),
        )?;

        draw_padded(
            &mut out,
            Color::Yellow,
            width,
            &format!("координаты x={:.1} y={:.1} z={:.1} | чанк {},{}", pos.0, pos.1, pos.2, cx, cz),
        )?;

        draw_padded(
            &mut out,
            Color::Green,
            width,
            &format!("пакетов принято {} | отправлено {}", client.in_cnt.values().sum::<u32>(), client.out_cnt.values().sum::<u32>()),
        )?;

        draw_line(
            &mut out,
            Color::DarkCyan,
            &format!("+{}+", "-".repeat(width - 2)),
        )?;

        if let Some(d) = deadline {
            let left = d.checked_duration_since(Instant::now())
                .map(|d| format!("{} сек", d.as_secs()))
                .unwrap_or_else(|| "вышло время".to_string());
            draw_padded(&mut out, Color::White, width, &format!("дедлайн через {}", left))?;
        }

        let text = if client.last_text_line.is_empty() {
            "чат: пока пусто".to_string()
        } else {
            format!("чат: {}", clean_one_line(&client.last_text_line))
        };
        draw_padded(&mut out, Color::Grey, width, &trim_for_width_outer(&text, inner))?;

        draw_padded(&mut out, Color::DarkGrey, width, "события")?;
        let visible: Vec<_> = client.event_log.iter().rev().take(5).rev().collect();
        for idx in 0..5 {
            if let Some(line) = visible.get(idx) {
                draw_padded(
                    &mut out,
                    Color::White,
                    width,
                    &format!("  {}", trim_for_width_outer(line, inner.saturating_sub(2))),
                )?;
            } else {
                draw_padded(&mut out, Color::White, width, "")?;
            }
        }

        draw_line(
            &mut out,
            Color::DarkCyan,
            &format!("+{}+", "-".repeat(width - 2)),
        )?;

        draw_padded(
            &mut out,
            Color::Cyan,
            width,
            &format!("> {}", trim_for_width_outer(&self.input, inner.saturating_sub(2))),
        )?;

        draw_padded(
            &mut out,
            Color::DarkGrey,
            width,
            "Enter — отправить, Esc — очистить, Ctrl+C — выйти",
        )?;

        out.flush()
    }
}

impl Drop for LiveTerminal {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = execute!(out, cursor::Show, terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

fn draw_line<W: Write>(out: &mut W, color: Color, text: &str) -> io::Result<()> {
    queue!(
        out,
        terminal::Clear(ClearType::CurrentLine),
        SetForegroundColor(color),
        Print(text),
        ResetColor,
        Print("\r\n")
    )?;
    Ok(())
}

fn draw_padded<W: Write>(out: &mut W, color: Color, width: usize, text: &str) -> io::Result<()> {
    let content_width = width.saturating_sub(4);
    let text = trim_for_width_outer(text, content_width);
    let pad = content_width.saturating_sub(text.len());
    queue!(
        out,
        terminal::Clear(ClearType::CurrentLine),
        SetForegroundColor(Color::DarkCyan),
        Print("| "),
        SetForegroundColor(color),
        Print(text),
        Print(" ".repeat(pad)),
        SetForegroundColor(Color::DarkCyan),
        Print(" |"),
        ResetColor,
        Print("\r\n")
    )?;
    Ok(())
}

fn spinner(frame: usize) -> &'static str {
    ["|", "/", "-", "\\"][frame % 4]
}

fn trim_for_width_outer(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    if max <= 3 {
        return ".".repeat(max);
    }
    let mut out = String::new();
    for ch in text.chars() {
        if out.len() + ch.len_utf8() > max - 3 {
            break;
        }
        out.push(ch);
    }
    out.push_str("...");
    out
}

fn clean_one_line(text: &str) -> String {
    text.replace('\n', " ").replace('\r', " ")
}

use std::time::Duration;