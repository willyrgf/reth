#![allow(dead_code, unreachable_pub)]
use reth_db::database::Database;
use reth_db::tables;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
        MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    terminal::Frame,
    text::{Span, Spans, Text},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    widgets::{List, ListItem, ListState},
    Terminal,
};

mod list;
mod utils;

/// Why did we wake up drawing thread?
enum Interrupt {
    KeyPressed(KeyEvent),
    MouseEvent(MouseEvent),
    IntervalElapsed,
}

/// Used to indicate why the UI stopped
pub enum TUIExitReason {
    /// Exit using <q>
    CharExit,
}

/// A terminal UI which holds a reference to the Database and otherwise manages all the user's
/// commands.
pub struct Gui<'a, DB: Database, B: Backend> {
    /// The database we're reading from
    db: &'a DB,
    /// The actual terminal
    terminal: Terminal<B>,
    /// Buffer for keys prior to execution, i.e. '10' + 'k' => move up 10 operations
    key_buffer: String,

    state: State,
}

#[derive(Clone, Default, Debug)]
struct State {}

impl<'a, DB: Database, B: Backend> Gui<'a, DB, B> {
    pub fn new(db: &'a DB) -> Self {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.hide_cursor()?;
        Self { db, terminal, key_buffer: String::new(), state: Default::default() }
    }

    pub async fn run(&mut self) -> eyre::Result<TUIExitReason> {
        // If something panics inside here, we should do everything we can to
        // not corrupt the user's terminal.
        std::panic::set_hook(Box::new(|e| {
            disable_raw_mode().expect("Unable to disable raw mode");
            execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)
                .expect("unable to execute disable mouse capture");
            println!("{e}");
        }));
        // This is the recommend tick rate from tui-rs, based on their examples
        let tick_rate = Duration::from_millis(200);

        // Setup a channel to send interrupts
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                // Poll events since last tick - if last tick is greater than tick_rate, we demand
                // immediate availability of the event. This may affect
                // interactivity, but I'm not sure as it is hard to test.
                if event::poll(tick_rate.saturating_sub(last_tick.elapsed())).unwrap() {
                    let event = event::read().unwrap();
                    if let Event::Key(key) = event {
                        if tx.send(Interrupt::KeyPressed(key)).is_err() {
                            return;
                        }
                    } else if let Event::Mouse(mouse) = event {
                        if tx.send(Interrupt::MouseEvent(mouse)).is_err() {
                            return;
                        }
                    }
                }
                // Force update if time has passed
                if last_tick.elapsed() > tick_rate {
                    if tx.send(Interrupt::IntervalElapsed).is_err() {
                        return;
                    }
                    last_tick = Instant::now();
                }
            }
        });

        loop {
            match rx.recv()? {
                // Key press
                Interrupt::KeyPressed(event) => match event.code {
                    // Exit
                    KeyCode::Char('q') => {
                        disable_raw_mode()?;
                        execute!(
                            terminal.backend_mut(),
                            LeaveAlternateScreen,
                            DisableMouseCapture
                        )?;
                        return Ok(TUIExitReason::CharExit);
                    }
                    // Move down
                    KeyCode::Char('j') | KeyCode::Down => {
                        // Grab number of times to do it
                        for _ in 0..buffer_as_number(&self.key_buffer, 1) {
                            // self.tables_list_state.
                            // if event.modifiers.contains(KeyModifiers::CONTROL) {
                            //     let max_mem = (debug_call[draw_memory.inner_call_index].1
                            //         [self.current_step]
                            //         .memory
                            //         .len()
                            //         / 32)
                            //         .saturating_sub(1);
                            //     if draw_memory.current_mem_startline < max_mem {
                            //         draw_memory.current_mem_startline += 1;
                            //     }
                            // } else if self.current_step < opcode_list.len() - 1 {
                            //     self.current_step += 1;
                            // } else if draw_memory.inner_call_index < debug_call.len() - 1 {
                            //     draw_memory.inner_call_index += 1;
                            //     self.current_step = 0;
                            // }
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('J') => {
                        for _ in 0..buffer_as_number(&self.key_buffer, 1) {
                            // let max_stack = debug_call[draw_memory.inner_call_index].1
                            //     [self.current_step]
                            //     .stack
                            //     .len()
                            //     .saturating_sub(1);
                            // if draw_memory.current_stack_startline < max_stack {
                            //     draw_memory.current_stack_startline += 1;
                            // }
                        }
                        self.key_buffer.clear();
                    }
                    // Move up
                    KeyCode::Char('k') | KeyCode::Up => {
                        for _ in 0..buffer_as_number(&self.key_buffer, 1) {
                            // if event.modifiers.contains(KeyModifiers::CONTROL) {
                            //     draw_memory.current_mem_startline =
                            //         draw_memory.current_mem_startline.saturating_sub(1);
                            // } else if self.current_step > 0 {
                            //     self.current_step -= 1;
                            // } else if draw_memory.inner_call_index > 0 {
                            //     draw_memory.inner_call_index -= 1;
                            //     self.current_step =
                            //         debug_call[draw_memory.inner_call_index].1.len() - 1;
                            // }
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('K') => {
                        for _ in 0..buffer_as_number(&self.key_buffer, 1) {
                            // draw_memory.current_stack_startline =
                            //     draw_memory.current_stack_startline.saturating_sub(1);
                        }
                        self.key_buffer.clear();
                    }
                    // Go to top of file
                    KeyCode::Char('g') => {
                        // draw_memory.inner_call_index = 0;
                        self.current_step = 0;
                        self.key_buffer.clear();
                    }
                    // Go to bottom of file
                    KeyCode::Char('G') => {
                        // draw_memory.inner_call_index = debug_call.len() - 1;
                        // self.current_step = debug_call[draw_memory.inner_call_index].1.len() - 1;
                        self.key_buffer.clear();
                    }
                    // // toggle stack labels
                    // KeyCode::Char('t') => {
                    //     stack_labels = !stack_labels;
                    // }
                    // // toggle memory utf8 decoding
                    // KeyCode::Char('m') => {
                    //     mem_utf = !mem_utf;
                    // }
                    KeyCode::Char(other) => match other {
                        '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => {
                            self.key_buffer.push(other);
                        }
                        _ => {
                            // Invalid key, clear buffer
                            self.key_buffer.clear();
                        }
                    },
                    _ => {
                        self.key_buffer.clear();
                    }
                },
                Interrupt::MouseEvent(event) => match event.kind {
                    MouseEventKind::ScrollUp => {
                        // if self.current_step > 0 {
                        //     self.current_step -= 1;
                        // } else if draw_memory.inner_call_index > 0 {
                        //     draw_memory.inner_call_index -= 1;
                        //     draw_memory.current_mem_startline = 0;
                        //     draw_memory.current_stack_startline = 0;
                        //     self.current_step = debug_call[draw_memory.inner_call_index].1.len() - 1;
                        // }
                    }
                    MouseEventKind::ScrollDown => {
                        // if self.current_step < opcode_list.len() - 1 {
                        //     self.current_step += 1;
                        // } else if draw_memory.inner_call_index < debug_call.len() - 1 {
                        //     draw_memory.inner_call_index += 1;
                        //     draw_memory.current_mem_startline = 0;
                        //     draw_memory.current_stack_startline = 0;
                        //     self.current_step = 0;
                        // }
                    }
                    _ => {}
                },
                Interrupt::IntervalElapsed => {}
            }

            terminal.draw(|f| {
                let [app, footer] = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Ratio(98, 100), Constraint::Ratio(2, 100)].as_ref())
                    .split(f.size())[..] else { panic!("Could not generate app/footer split") };

                let [table_selection, table_output] = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)].as_ref())
                    .split(app)[..] else { panic!("Could not generate app/footer split") };

                self.draw_footer(f, footer);
                self.draw_tables(f, table_selection);
                self.draw_outputs(f, table_output);
            })?;
        }

        // unreachable!("This should never be hit as we're in the event loop")

        // terminal.clear()?;
        // Ok(TUIExitReason::CharExit)
    }

    fn draw_tables<B: Backend>(&mut self, f: &mut Frame<'_, B>, area: Rect) {
        let tables =
            Block::default().title("Tables").borders(Borders::ALL).border_type(BorderType::Rounded);
        let mut text_output: Vec<Spans<'_>> = Vec::new();

        // let bg_color = if line_number == current_step { Color::DarkGray } else { Color::Reset };
        let bg_color = Color::Reset;

        let tables_list =
            tables::TABLES.iter().map(|(_, name)| ListItem::new(*name)).collect::<Vec<_>>();
        let list = List::new(tables_list)
            .block(Block::default().title("List").borders(Borders::ALL))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().add_modifier(Modifier::ITALIC))
            .highlight_symbol(">>");

        // let paragraph = Paragraph::new(text_output)
        //     .list(list)
        //     .block(Default::default())
        //     .wrap(Wrap { trim: false });
        f.render_stateful_widget(list, area, &mut self.tables_list_state);
    }

    fn draw_outputs<B: Backend>(&mut self, f: &mut Frame<'_, B>, area: Rect) {
        let tables = Block::default().title("Values").borders(Borders::ALL);
        let mut text_output: Vec<Spans<'_>> = Vec::new();

        // let bg_color = if line_number == current_step { Color::DarkGray } else { Color::Reset };
        let bg_color = Color::Reset;

        text_output.push(Spans::from(Span::styled(
            format!("Lol"),
            Style::default().fg(Color::White).bg(bg_color),
        )));

        let paragraph =
            Paragraph::new(text_output).block(Default::default()).wrap(Wrap { trim: false });
        f.render_widget(paragraph, area);
    }

    fn draw_footer<B: Backend>(&mut self, f: &mut Frame<'_, B>, area: Rect) {
        let block_controls = Block::default();

        let text_output = Text::from(Span::styled(
            "[q]: quit | [k/j]: prev/next item | [g/G]: start/end | [TAB]: switch panes",
            Style::default().add_modifier(Modifier::DIM),
        ));
        let paragraph = Paragraph::new(text_output)
            .block(block_controls)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false });
        f.render_widget(paragraph, area);
    }
}

/// Grab number from buffer. Used for something like '10k' to move up 10 operations
fn buffer_as_number(buffer: &str, default_value: usize) -> usize {
    if let Ok(num) = buffer.parse() {
        if num >= 1 {
            num
        } else {
            default_value
        }
    } else {
        default_value
    }
}
