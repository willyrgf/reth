use std::collections::HashMap;
use std::fmt::Display;

use serde::Serialize;
use tui::backend::Backend;
use tui::layout::Rect;
use tui::style::*;
use tui::terminal::Frame;
use tui::widgets::Block;
use tui::widgets::Borders;
use tui::widgets::{self, TableState};
use tui::widgets::{Cell, Row};

#[derive(Clone, Debug)]
pub struct Table<T> {
    title: String,
    // each row in the table
    items: Vec<T>,
    state: TableState,
}

impl Table<HashMap<String, serde_json::Value>> {
    pub fn new(title: &str, items: Vec<HashMap<String, serde_json::Value>>) -> Self {
        let mut state = TableState::default();
        state.select(Some(0));
        Self { title: title.to_owned(), items, state }
    }

    /// Renders the component and highlights accordingly.
    pub fn render<B: Backend>(
        &mut self,
        f: &mut Frame<'_, B>,
        area: Rect,
        focused: bool,
    ) -> eyre::Result<()> {
        let mut rows = Vec::new();
        for item in self.items.iter() {
            let cells =
                item.values().map(|value| Cell::from(value.to_string())).collect::<Vec<_>>();
            rows.push(Row::new(cells));
        }

        let keys =
            self.items[0].keys().map(|value| Cell::from(value.to_string())).collect::<Vec<_>>();
        let header = Row::new(keys);
        let table = widgets::Table::new(rows)
            .header(header)
            .block(Block::default().title(self.title.clone()).borders(Borders::ALL))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan))
            .highlight_symbol(">>");

        // Render it
        f.render_stateful_widget(table, area, &mut self.state);
        Ok(())
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    // Select the previous item. This will not be reflected until the widget is drawn in the
    // `Terminal::draw` callback using `Frame::render_stateful_widget`.
    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn select(&mut self, index: usize) {
        self.state.select(Some(index));
    }

    // Unselect the currently selected item if any. The implementation of `TableState` makes
    // sure that the stored offset is also reset.
    pub fn unselect(&mut self) {
        self.state.select(None);
    }
}
