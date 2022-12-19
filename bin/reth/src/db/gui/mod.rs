#![allow(dead_code, unreachable_pub)]
use reth_db::database::Database;
use reth_db::tables;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use eyre::Result;
use std::{
    collections::HashMap,
    io::{self, Stdout},
};

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

use super::{DbTool, ListArgs};

mod list;
mod table;
mod utils;

/// A terminal UI which holds a reference to the Database and otherwise manages all the user's
/// commands.
pub struct Gui<'a, DB: Database, B: Backend> {
    /// The actual terminal
    terminal: Terminal<B>,

    /// Our application's state
    state: State<'a, DB>,
}

enum ActiveComponent {
    SelectTable,
    Values,
}

#[derive(Clone, Debug)]
struct State<'a, DB: Database> {
    /// The database we're reading from
    db: &'a DB,

    tables_list: list::List<String>,
    values_table: Option<table::Table<HashMap<String, serde_json::Value>>>,
}

impl<'a, DB: Database> State<'a, DB> {
    pub fn next(&mut self, select_table: bool) {
        if select_table {
            self.tables_list.next()
        } else {
            // This should make a query to the DB walker from the starting index,
            let mut tool = DbTool::new(self.db).unwrap();
            let selected_table_idx = self.tables_list.state.selected().unwrap();
            let table = self.tables_list.items[selected_table_idx].to_string();
            let values = tool.list(&ListArgs { table: table.clone(), start: 0, len: 1 }).unwrap();
            self.values_table = Some(table::Table::new(&table, values));
        }
    }

    pub fn previous(&mut self, select_table: bool) {
        if select_table {
            self.tables_list.previous()
        } else {
            // self.data.previous()
        }
    }
}

impl<'a, DB: Database> Gui<'a, DB, CrosstermBackend<Stdout>> {
    /// Instantiates a new TUI.
    pub fn new(db: &'a DB) -> eyre::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.hide_cursor()?;

        // If something panics inside here, we should do everything we can to
        // not corrupt the user's terminal.
        std::panic::set_hook(Box::new(|e| {
            disable_raw_mode().expect("Unable to disable raw mode");
            execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)
                .expect("unable to execute disable mouse capture");
            println!("{e}");
        }));

        Ok(Self {
            terminal,
            state: State {
                db,
                tables_list: list::List::new(
                    "Tables",
                    tables::TABLES.iter().map(|(_, name)| name.to_string()).collect::<Vec<_>>(),
                ),
                values_table: None,
            },
        })
    }
}

impl<'a, DB: Database, B: Backend> Gui<'a, DB, B> {
    pub fn run(&mut self) -> io::Result<()> {
        // clear the page
        self.terminal.clear()?;

        loop {
            // re-render
            let state = &mut self.state;
            self.terminal.draw(|f| {
                render(f, state).expect("could not render; qed");
            })?;

            // Adjust the state
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => {
                        disable_raw_mode()?;
                        execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
                        return Ok(());
                    }
                    KeyCode::Down => self.state.next(key.modifiers.contains(KeyModifiers::SHIFT)),
                    KeyCode::Up => self.state.previous(key.modifiers.contains(KeyModifiers::SHIFT)),
                    _ => {}
                }
            }
        }
    }
}

fn render<B: Backend, DB: Database>(f: &mut Frame<'_, B>, state: &mut State<'_, DB>) -> Result<()> {
    // Split things up
    let [app, footer] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Ratio(98, 100), Constraint::Ratio(2, 100)].as_ref())
            .split(f.size())[..] else { panic!("Could not generate app/footer split") };

    let [table_selection, table_output] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)].as_ref())
            .split(app)[..] else { panic!("Could not generate tables / values split") };

    draw_footer(f, footer);
    state.tables_list.render(f, table_selection, true)?;
    if let Some(values) = state.values_table.as_mut() {
        values.render(f, table_output, true)?;
    }
    Ok(())
}

fn draw_footer<B: Backend>(f: &mut Frame<'_, B>, area: Rect) {
    let block_controls = Block::default();

    let text_output = Text::from(Span::styled(
        "[q]: quit | [up/down]: prev/next item | [SHIFT + up/down]: prev/next table",
        Style::default().add_modifier(Modifier::DIM),
    ));
    let paragraph = Paragraph::new(text_output)
        .block(block_controls)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}
