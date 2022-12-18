use tui::backend::Backend;
use tui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use tui::terminal::Frame;
use tui::widgets::{ListItem, ListState};

struct List<T> {
    items: Vec<T>,
    state: ListState,
}

impl<T: Clone> List<T> {
    pub fn render<B: Backend>(
        &self,
        f: &mut Frame<'_, B>,
        area: Rect,
        focused: bool,
    ) -> eyre::Result<()> {
        let items = self.items.iter().cloned().map(|item| ListItem::new(item)).collect::<Vec<_>>();
        let list = tui::widgets::List::new(items);
        f.render_stateful_widget(list, area, &mut self.state);
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

    // Unselect the currently selected item if any. The implementation of `ListState` makes
    // sure that the stored offset is also reset.
    pub fn unselect(&mut self) {
        self.state.select(None);
    }
}
