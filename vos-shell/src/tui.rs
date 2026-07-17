//! A ratatui console for a VOS space: a tabbed TUI driving the sandboxed
//! [`ConsoleEngine`]. Tabs:
//!
//! * **<space>** — a nu-script prompt + scrollback; actors are commands. The
//!   tab is titled with the space name (it's a session; later we'll open more
//!   tabs for parallel sessions).
//! * **Browser** — every installed actor's messages with their signatures;
//!   Enter drops `<agent> <method> ` into the prompt.
//! * **Help** — key bindings.
//!
//! The prompt is borderless — only a top and bottom rule separate it from the
//! scrollback — and grows to multiple lines: a trailing `\` before Enter is a
//! soft newline, so nu scripts can span lines before they're submitted.
//!
//! The input editor is a small hand-rolled widget (not reedline, which owns the
//! terminal and conflicts with ratatui's draw loop). The whole state machine
//! lives in [`App::on_key`] / [`App::render`] as pure functions so it is
//! testable against a `TestBackend` without a real terminal — see the tests.

use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use ratatui::{Frame, Terminal};

use crate::backend::BackendError;
use crate::discovery::SchemaCache;
use crate::engine::ConsoleEngine;
use crate::highlight::HlKind;

/// Run the TUI on the real terminal until the user quits. `label` is shown in
/// the prompt/title (typically the space name). Sets up/tears down the
/// alternate screen + raw mode via ratatui's helpers.
pub fn run(engine: ConsoleEngine, label: &str) -> anyhow::Result<()> {
    let mut app = App::new(engine)?.with_label(label);
    let mut terminal = ratatui::init();
    let result = app.event_loop(&mut terminal);
    ratatui::restore();
    result
}

/// Visible width of the `> ` prompt (and of the blank continuation prefix).
const PROMPT_WIDTH: u16 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Console,
    Browser,
    Help,
}

impl Tab {
    fn index(self) -> usize {
        match self {
            Tab::Console => 0,
            Tab::Browser => 1,
            Tab::Help => 2,
        }
    }
}

/// One rendered scrollback line and how to colour it.
enum Out {
    Prompt(String),
    Ok(String),
    Err(String),
}

/// One selectable command in the Browser: `<agent> <method>` + a rendered
/// signature.
#[derive(Clone)]
struct Cmd {
    agent: String,
    method: String,
    signature: String,
    is_query: bool,
}

pub struct App {
    engine: ConsoleEngine,
    space_label: String,
    tab: Tab,
    // Console state
    input: String,
    cursor: usize, // byte offset into `input`
    output: Vec<Out>,
    scroll: u16,
    history: Vec<String>,
    history_pos: Option<usize>,
    // Browser state
    cmds: Vec<Cmd>,
    browser: ListState,
    should_quit: bool,
}

impl App {
    pub fn new(engine: ConsoleEngine) -> Result<Self, BackendError> {
        let cmds = Self::load_cmds(&engine);
        let mut browser = ListState::default();
        if !cmds.is_empty() {
            browser.select(Some(0));
        }
        let mut app = App {
            engine,
            space_label: "space".to_string(),
            tab: Tab::Console,
            input: String::new(),
            cursor: 0,
            output: Vec::new(),
            scroll: 0,
            history: Vec::new(),
            history_pos: None,
            cmds,
            browser,
            should_quit: false,
        };
        app.output.push(Out::Ok(format!(
            "{} actor command(s). Shift-Tab switches tabs · type a command and Tab \
             completes · `help` for keys.",
            app.cmds.len()
        )));
        Ok(app)
    }

    /// Override the label shown in the prompt / title (e.g. the space name).
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.space_label = label.into();
        self
    }

    fn load_cmds(engine: &ConsoleEngine) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        if let Ok(cache) = SchemaCache::load(engine.client().as_ref()) {
            let mut agents: Vec<_> = cache
                .agents
                .iter()
                .map(|a| a.instance_name.clone())
                .collect();
            agents.sort();
            for agent in agents {
                if let Some(meta) = cache.schemas.get(&agent) {
                    for msg in &meta.messages {
                        let signature = msg
                            .fields
                            .iter()
                            .map(|f| format!("{}: {}", f.name, f.ty))
                            .collect::<Vec<_>>()
                            .join(", ");
                        cmds.push(Cmd {
                            agent: agent.clone(),
                            method: msg.name.clone(),
                            signature,
                            is_query: msg.is_query,
                        });
                    }
                }
            }
        }
        cmds
    }

    fn event_loop<B: ratatui::backend::Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
    ) -> anyhow::Result<()> {
        while !self.should_quit {
            terminal.draw(|f| self.render(f))?;
            if event::poll(Duration::from_millis(200))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.on_key(key);
                    }
                }
            }
        }
        Ok(())
    }

    // ── input editing ────────────────────────────────────────────────────

    fn insert_char(&mut self, c: char) {
        self.input.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.input[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.input.replace_range(prev..self.cursor, "");
        self.cursor = prev;
    }

    fn cursor_left(&mut self) {
        if let Some((i, _)) = self.input[..self.cursor].char_indices().next_back() {
            self.cursor = i;
        }
    }

    fn cursor_right(&mut self) {
        if let Some(c) = self.input[self.cursor..].chars().next() {
            self.cursor += c.len_utf8();
        }
    }

    // ── command handling ─────────────────────────────────────────────────

    /// Public for tests: feed a key event to the state machine.
    pub fn on_key(&mut self, key: KeyEvent) {
        // Global quit chords.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d'))
        {
            self.should_quit = true;
            return;
        }
        // Tab navigation works on any tab. `Tab` is reserved for completion,
        // so switching uses Shift-Tab (cycle) and Ctrl-Left/Right.
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::BackTab => {
                self.next_tab();
                return;
            }
            KeyCode::Right if ctrl => {
                self.next_tab();
                return;
            }
            KeyCode::Left if ctrl => {
                self.prev_tab();
                return;
            }
            KeyCode::Up if ctrl => {
                self.scroll = self.scroll.saturating_sub(3);
                return;
            }
            KeyCode::Down if ctrl => {
                self.scroll = self.scroll.saturating_add(3);
                return;
            }
            _ => {}
        }
        match self.tab {
            Tab::Console => self.console_key(key),
            Tab::Browser => self.browser_key(key),
            Tab::Help => {}
        }
    }

    fn next_tab(&mut self) {
        self.tab = match self.tab {
            Tab::Console => Tab::Browser,
            Tab::Browser => Tab::Help,
            Tab::Help => Tab::Console,
        };
    }

    fn prev_tab(&mut self) {
        self.tab = match self.tab {
            Tab::Console => Tab::Help,
            Tab::Browser => Tab::Console,
            Tab::Help => Tab::Browser,
        };
    }

    fn console_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.on_enter(),
            KeyCode::Tab => self.complete(),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Left => self.cursor_left(),
            KeyCode::Right => self.cursor_right(),
            KeyCode::Up => self.history_prev(),
            KeyCode::Down => self.history_next(),
            KeyCode::Esc => self.should_quit = true,
            KeyCode::Char(c) => self.insert_char(c),
            _ => {}
        }
    }

    fn browser_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.browser_move(-1),
            KeyCode::Down => self.browser_move(1),
            KeyCode::Enter => {
                if let Some(i) = self.browser.selected() {
                    if let Some(cmd) = self.cmds.get(i) {
                        self.input = format!("{} {} ", cmd.agent, cmd.method);
                        self.cursor = self.input.len();
                        self.tab = Tab::Console;
                    }
                }
            }
            KeyCode::Esc => self.tab = Tab::Console,
            _ => {}
        }
    }

    fn browser_move(&mut self, delta: isize) {
        if self.cmds.is_empty() {
            return;
        }
        let cur = self.browser.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(self.cmds.len() as isize) as usize;
        self.browser.select(Some(next));
    }

    fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let pos = match self.history_pos {
            Some(0) => 0,
            Some(p) => p - 1,
            None => self.history.len() - 1,
        };
        self.history_pos = Some(pos);
        self.input = self.history[pos].clone();
        self.cursor = self.input.len();
    }

    fn history_next(&mut self) {
        match self.history_pos {
            Some(p) if p + 1 < self.history.len() => {
                self.history_pos = Some(p + 1);
                self.input = self.history[p + 1].clone();
            }
            Some(_) => {
                self.history_pos = None;
                self.input.clear();
            }
            None => {}
        }
        self.cursor = self.input.len();
    }

    /// Tab-completion against agent names (first token) and an agent's method
    /// names (second token). Completes to the longest common prefix; appends a
    /// space on a unique agent/method match.
    fn complete(&mut self) {
        let trimmed_start = self.input.trim_start();
        let tokens: Vec<&str> = trimmed_start.split_whitespace().collect();
        let trailing_space = self.input.ends_with(' ');

        let (candidates, replace_from): (Vec<String>, usize) = if tokens.is_empty() {
            (self.agent_names(), self.input.len())
        } else if tokens.len() == 1 && !trailing_space {
            // completing the agent name
            let prefix = tokens[0];
            let cands: Vec<String> = self
                .agent_names()
                .into_iter()
                .filter(|a| a.starts_with(prefix))
                .collect();
            (cands, self.input.len() - prefix.len())
        } else {
            // completing a method of tokens[0]
            let agent = tokens[0];
            let method_prefix = if trailing_space {
                ""
            } else {
                tokens.last().copied().unwrap_or("")
            };
            let cands: Vec<String> = self
                .methods_of(agent)
                .into_iter()
                .filter(|m| m.starts_with(method_prefix))
                .collect();
            (cands, self.input.len() - method_prefix.len())
        };

        if candidates.is_empty() {
            return;
        }
        let common = longest_common_prefix(&candidates);
        if common.is_empty() {
            return;
        }
        self.input.truncate(replace_from);
        self.input.push_str(&common);
        if candidates.len() == 1 {
            self.input.push(' ');
        }
        self.cursor = self.input.len();
    }

    fn agent_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.cmds.iter().map(|c| c.agent.clone()).collect();
        names.sort();
        names.dedup();
        names
    }

    fn methods_of(&self, agent: &str) -> Vec<String> {
        self.cmds
            .iter()
            .filter(|c| c.agent == agent)
            .map(|c| c.method.clone())
            .collect()
    }

    /// Enter: a trailing `\` immediately before the cursor is a soft newline
    /// (continue a multi-line nu script); otherwise submit the whole buffer.
    fn on_enter(&mut self) {
        if self.input[..self.cursor].ends_with('\\') {
            self.cursor -= 1; // ASCII '\'
            self.input.remove(self.cursor);
            self.insert_char('\n');
        } else {
            self.submit();
        }
    }

    fn submit(&mut self) {
        let line = self.input.trim().to_string();
        self.input.clear();
        self.cursor = 0;
        self.history_pos = None;
        if line.is_empty() {
            return;
        }
        // Echo the (possibly multi-line) command, prompt on the first row and
        // an aligned continuation prefix on the rest.
        for (i, l) in line.lines().enumerate() {
            let prefix = if i == 0 { "> " } else { "  " };
            self.output.push(Out::Prompt(format!("{prefix}{l}")));
        }
        self.history.push(line.clone());
        match line.as_str() {
            "exit" | "quit" => {
                self.should_quit = true;
                return;
            }
            "clear" => {
                self.output.clear();
                return;
            }
            _ => {}
        }
        let result = self.engine.eval(&line);
        if result.output.is_empty() && !result.is_error {
            self.output.push(Out::Ok("(ok)".to_string()));
        } else {
            for l in result.output.lines() {
                if result.is_error {
                    self.output.push(Out::Err(l.to_string()));
                } else {
                    self.output.push(Out::Ok(l.to_string()));
                }
            }
        }
        // Pin scroll to the bottom on new output.
        self.scroll = u16::MAX;
    }

    // ── rendering ────────────────────────────────────────────────────────

    /// Public for tests: render one frame.
    pub fn render(&mut self, frame: &mut Frame) {
        let [tabs_area, body] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(frame.area());

        // Paint the whole header row a contrasting background, then lay the
        // tab titles over it (active tab inverted). No numbers, no padding rows.
        let header_bg = Color::DarkGray;
        frame.render_widget(
            Block::default().style(Style::default().bg(header_bg)),
            tabs_area,
        );
        // The first tab is the session, titled with the space name (later:
        // multiple session tabs); then the fixed Browser / Help views.
        let titles = [self.space_label.as_str(), "Browser", "Help"];
        let tabs = Tabs::new(
            titles
                .iter()
                .map(|t| Line::from(format!(" {t} ")))
                .collect::<Vec<_>>(),
        )
        .select(self.tab.index())
        .style(Style::default().fg(Color::Gray).bg(header_bg))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .divider("")
        .padding("", "");
        frame.render_widget(tabs, tabs_area);

        match self.tab {
            Tab::Console => self.render_console(frame, body),
            Tab::Browser => self.render_browser(frame, body),
            Tab::Help => self.render_help(frame, body),
        }
    }

    fn render_console(&mut self, frame: &mut Frame, area: Rect) {
        // The prompt grows with the number of (soft) input lines; +2 for the
        // top and bottom rules. Cap it so the scrollback never disappears.
        let input_rows = self.input.split('\n').count() as u16;
        let max_in = (area.height / 2).max(3);
        let in_height = (input_rows + 2).clamp(3, max_in);
        let [out_area, in_area] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(in_height)]).areas(area);

        let lines: Vec<Line> = self
            .output
            .iter()
            .map(|o| match o {
                Out::Prompt(s) => Line::from(s.clone()).fg(Color::DarkGray),
                Out::Ok(s) => Line::from(s.clone()),
                Out::Err(s) => Line::from(s.clone()).fg(Color::Red),
            })
            .collect();

        // Clamp scroll so the latest output is visible (no borders to subtract).
        let total = lines.len() as u16;
        let max_scroll = total.saturating_sub(out_area.height);
        let scroll = self.scroll.min(max_scroll);
        self.scroll = scroll;

        // Borderless scrollback — clean, like the surrounding harness.
        let output = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0));
        frame.render_widget(output, out_area);

        // Prompt: only a top + bottom rule frame it (no box). nu-highlighted,
        // possibly multi-line, with a `> ` prompt and aligned continuations.
        let block = Block::default().borders(Borders::TOP | Borders::BOTTOM);
        let inner = block.inner(in_area);
        frame.render_widget(block, in_area);
        frame.render_widget(Paragraph::new(self.input_lines()), inner);

        // Cursor: which soft-line it's on + the column past the `> ` prompt.
        let before = &self.input[..self.cursor];
        let line_idx = before.matches('\n').count() as u16;
        let col_in_line = before.rsplit('\n').next().unwrap_or("").chars().count() as u16;
        let col = inner.x + PROMPT_WIDTH + col_in_line;
        let row = inner.y + line_idx;
        frame.set_cursor_position(Position::new(col, row));
    }

    /// Build the prompt's rendered lines: the nu-highlighted input split on
    /// newlines, each row prefixed with the `> ` prompt (first) or an aligned
    /// blank continuation (rest).
    fn input_lines(&self) -> Vec<Line<'static>> {
        // Distribute highlighted runs across visual rows, splitting on '\n'.
        let mut rows: Vec<Vec<Span<'static>>> = vec![Vec::new()];
        for run in self.engine.highlight(&self.input) {
            let style = Style::default().fg(hl_color(run.kind));
            let mut segs = run.text.split('\n');
            if let Some(first) = segs.next() {
                if !first.is_empty() {
                    rows.last_mut()
                        .unwrap()
                        .push(Span::styled(first.to_string(), style));
                }
            }
            for seg in segs {
                let mut row = Vec::new();
                if !seg.is_empty() {
                    row.push(Span::styled(seg.to_string(), style));
                }
                rows.push(row);
            }
        }
        rows.into_iter()
            .enumerate()
            .map(|(i, mut spans)| {
                let prefix = if i == 0 {
                    Span::from("> ").fg(Color::Cyan)
                } else {
                    Span::from("  ")
                };
                let mut out = Vec::with_capacity(spans.len() + 1);
                out.push(prefix);
                out.append(&mut spans);
                Line::from(out)
            })
            .collect()
    }

    fn render_browser(&mut self, frame: &mut Frame, area: Rect) {
        let [list_area, detail_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(area);

        let items: Vec<ListItem> = self
            .cmds
            .iter()
            .map(|c| {
                let tag = if c.is_query { "?" } else { "!" };
                ListItem::new(format!("{tag} {} {}", c.agent, c.method))
            })
            .collect();
        let list = List::new(items)
            .block(Block::bordered().title(" actors (?=query !=action) "))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(list, list_area, &mut self.browser);

        let detail = match self.browser.selected().and_then(|i| self.cmds.get(i)) {
            Some(c) => {
                let args = if c.signature.is_empty() {
                    "(no arguments)".to_string()
                } else {
                    c.signature.clone()
                };
                vec![
                    Line::from(format!("{} {}", c.agent, c.method)).add_modifier(Modifier::BOLD),
                    Line::from(""),
                    Line::from(format!("args: {args}")),
                    Line::from(format!(
                        "kind: {}",
                        if c.is_query {
                            "query (read-only)"
                        } else {
                            "action (write)"
                        }
                    )),
                    Line::from(""),
                    Line::from("Enter → insert into prompt").fg(Color::DarkGray),
                ]
            }
            None => vec![Line::from("no actors installed").fg(Color::DarkGray)],
        };
        frame.render_widget(
            Paragraph::new(detail)
                .block(Block::bordered().title(" detail "))
                .wrap(Wrap { trim: false }),
            detail_area,
        );
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = crate::sandbox::CONSOLE_HELP
            .lines()
            .map(|l| Line::from(l.to_string()))
            .collect();
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::bordered().title(" help "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
}

/// Map a syntax category to a prompt colour.
fn hl_color(kind: HlKind) -> Color {
    match kind {
        HlKind::Command => Color::Cyan,
        HlKind::External => Color::LightRed,
        HlKind::Flag => Color::LightYellow,
        HlKind::String => Color::Green,
        HlKind::Number => Color::Magenta,
        HlKind::Variable => Color::LightCyan,
        HlKind::Keyword => Color::Blue,
        HlKind::Operator => Color::Yellow,
        HlKind::Garbage => Color::Red,
        HlKind::Plain => Color::Reset,
    }
}

fn longest_common_prefix(items: &[String]) -> String {
    let Some(first) = items.first() else {
        return String::new();
    };
    let mut end = first.len();
    for s in &items[1..] {
        end = end.min(s.len());
        while !s.is_char_boundary(end) || first[..end] != s[..end] {
            end -= 1;
            if end == 0 {
                return String::new();
            }
        }
    }
    first[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{AgentInfo, SpaceClient};
    use ratatui::backend::TestBackend;
    use std::sync::Arc;
    use vos::abi::service::ServiceId;
    use vos::metadata::{ParsedField, ParsedMessage, ParsedMeta};
    use vos::value::{Msg, Value};

    struct Mock {
        schema: ParsedMeta,
    }
    impl SpaceClient for Mock {
        fn list_agents(&self) -> Result<Vec<AgentInfo>, BackendError> {
            Ok(vec![AgentInfo {
                instance_name: "counter".into(),
                program_name: "counter".into(),
            }])
        }
        fn resolve_target(&self, _name: &str) -> Result<ServiceId, BackendError> {
            Ok(ServiceId(0x0101))
        }
        fn raw_meta(&self, _name: &str) -> Result<Vec<u8>, BackendError> {
            Ok(vec![])
        }
        fn schema(&self, _name: &str) -> Result<Option<ParsedMeta>, BackendError> {
            Ok(Some(self.schema.clone()))
        }
        fn invoke(&self, _t: ServiceId, msg: &Msg) -> Result<Value, BackendError> {
            if msg.name == "add" {
                let a = msg.args.get_u64("a").unwrap_or(0);
                let b = msg.args.get_u64("b").unwrap_or(0);
                Ok(Value::U64(a + b))
            } else {
                Ok(Value::Unit)
            }
        }
    }

    fn app() -> App {
        let schema = ParsedMeta {
            actor_name: "counter".into(),
            messages: vec![
                ParsedMessage {
                    name: "add".into(),
                    is_query: true,
                    fields: vec![
                        ParsedField {
                            name: "a".into(),
                            ty: "u64".into(),
                        },
                        ParsedField {
                            name: "b".into(),
                            ty: "u64".into(),
                        },
                    ],
                    exposed_to_cli: true,
                    returns: "u64".into(),
                    doc: String::new(),
                    timeout_ms: 0,
                    mode: 0,
                },
                ParsedMessage {
                    name: "reset".into(),
                    is_query: false,
                    fields: vec![],
                    exposed_to_cli: true,
                    returns: "()".into(),
                    doc: String::new(),
                    timeout_ms: 0,
                    mode: 0,
                },
            ],
            constructor: vec![],
            kind: 0,
            caps: vec![],
            doc: String::new(),
            provable: false,
        };
        let engine = ConsoleEngine::new(Arc::new(Mock { schema })).unwrap();
        App::new(engine).unwrap().with_label("demo")
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }
    fn typ(app: &mut App, s: &str) {
        for c in s.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    #[test]
    fn submit_runs_actor_command_and_shows_result() {
        let mut a = app();
        typ(&mut a, "counter add 2 3");
        press(&mut a, KeyCode::Enter);
        let shown: Vec<&str> = a
            .output
            .iter()
            .filter_map(|o| match o {
                Out::Ok(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(shown.contains(&"5"), "expected 5 in output, got {shown:?}");
        assert!(a.input.is_empty());
    }

    #[test]
    fn browser_lists_all_messages_and_enter_fills_prompt() {
        let mut a = app();
        assert_eq!(a.cmds.len(), 2, "counter has add + reset");
        a.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE)); // → Browser
        assert_eq!(a.tab.index(), Tab::Browser.index());
        press(&mut a, KeyCode::Enter); // select first (add)
        assert_eq!(a.tab.index(), Tab::Console.index());
        assert_eq!(a.input, "counter add ");
    }

    #[test]
    fn tab_completes_agent_then_method() {
        let mut a = app();
        typ(&mut a, "cou");
        press(&mut a, KeyCode::Tab);
        assert_eq!(a.input, "counter "); // unique agent → completed + space
        typ(&mut a, "ad");
        press(&mut a, KeyCode::Tab);
        assert_eq!(a.input, "counter add ");
    }

    #[test]
    fn shift_tab_and_ctrl_arrows_switch_tabs() {
        let mut a = app();
        assert_eq!(a.tab.index(), 0);
        a.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE)); // Console → Browser
        assert_eq!(a.tab.index(), 1);
        a.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL)); // → Console
        assert_eq!(a.tab.index(), 0);
        a.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL)); // → Browser
        assert_eq!(a.tab.index(), 1);
    }

    #[test]
    fn help_command_is_vos_specific() {
        let mut a = app();
        typ(&mut a, "help");
        press(&mut a, KeyCode::Enter);
        let joined: String = a
            .output
            .iter()
            .filter_map(|o| match o {
                Out::Ok(s) => Some(s.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("VOS space console"),
            "help should be VOS-specific, got: {joined}"
        );
    }

    #[test]
    fn bare_agent_name_lists_messages() {
        let mut a = app();
        typ(&mut a, "counter");
        press(&mut a, KeyCode::Enter);
        let shown: Vec<&str> = a
            .output
            .iter()
            .filter_map(|o| match o {
                Out::Ok(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            shown.iter().any(|l| l.contains("message(s)")),
            "bare agent should list messages, got {shown:?}"
        );
    }

    #[test]
    fn nu_builtin_data_command_works() {
        let mut a = app();
        typ(&mut a, "[1 2 3] | length");
        press(&mut a, KeyCode::Enter);
        let shown: Vec<&str> = a
            .output
            .iter()
            .filter_map(|o| match o {
                Out::Ok(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(shown.contains(&"3"), "expected `length` → 3, got {shown:?}");
    }

    #[test]
    fn backslash_enter_continues_then_submits_multiline() {
        let mut a = app();
        typ(&mut a, "[1 2 3] |");
        press(&mut a, KeyCode::Char('\\'));
        press(&mut a, KeyCode::Enter); // soft newline, not a submit
        assert_eq!(
            a.input, "[1 2 3] |\n",
            "backslash-enter should add a newline"
        );
        assert!(
            !a.output.iter().any(|o| matches!(o, Out::Prompt(_))),
            "continuation must not submit the command"
        );

        typ(&mut a, " length");
        press(&mut a, KeyCode::Enter); // now submit the whole script
        assert!(a.input.is_empty(), "the multi-line command should submit");
        let shown: Vec<&str> = a
            .output
            .iter()
            .filter_map(|o| match o {
                Out::Ok(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            shown.contains(&"3"),
            "multi-line pipeline should eval to 3, got {shown:?}"
        );
    }

    #[test]
    fn history_recalls_previous_command() {
        let mut a = app();
        typ(&mut a, "counter reset");
        press(&mut a, KeyCode::Enter);
        assert!(a.input.is_empty());
        press(&mut a, KeyCode::Up);
        assert_eq!(a.input, "counter reset");
    }

    #[test]
    fn sandbox_command_renders_as_error() {
        let mut a = app();
        typ(&mut a, "open /etc/passwd");
        press(&mut a, KeyCode::Enter);
        let has_err = a.output.iter().any(|o| matches!(o, Out::Err(_)));
        assert!(has_err, "sandbox rejection should render as an error line");
    }

    #[test]
    fn renders_to_test_backend_without_panicking() {
        let mut a = app();
        typ(&mut a, "counter add 2 3");
        press(&mut a, KeyCode::Enter);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| a.render(f)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let text: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(
            text.contains("demo"),
            "the session tab should be titled with the space name"
        );
        assert!(text.contains("Browser"), "tab bar should render");
        assert!(text.contains('5'), "result should be visible in the buffer");

        // Browser tab renders too.
        a.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
        terminal.draw(|f| a.render(f)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("counter"), "browser should list the actor");
    }

    #[test]
    fn ctrl_c_quits() {
        let mut a = app();
        a.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(a.should_quit);
    }
}
