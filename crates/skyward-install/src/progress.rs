//! Progress of a restore this build performs itself, reported to the screen.
//!
//! The staging and writing layers run on the installer thread, so a
//! thread-local sink keeps their signatures free of UI types while still
//! letting the install page show what is happening.
use crate::FactoryStep;
use std::cell::RefCell;

type Sink<'a> = Box<dyn FnMut(FactoryStep) + 'a>;

thread_local! {
    static SINK: RefCell<Option<Sink<'static>>> = const { RefCell::new(None) };
}

/// Report a step of the restore.
pub fn report(step: FactoryStep) {
    SINK.with(|slot| {
        if let Ok(mut held) = slot.try_borrow_mut()
            && let Some(sink) = held.as_mut()
        {
            sink(step);
        }
    });
}

/// Run `body` with `sink` receiving every report it makes.
pub fn with_sink<T>(sink: impl FnMut(FactoryStep) + 'static, body: impl FnOnce() -> T) -> T {
    SINK.with(|slot| *slot.borrow_mut() = Some(Box::new(sink) as Sink<'static>));
    let result = body();
    SINK.with(|slot| *slot.borrow_mut() = None);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn reports_reach_only_the_installed_sink() {
        report(FactoryStep::Publishing);
        let seen = std::rc::Rc::new(Cell::new(0));
        let counter = seen.clone();
        with_sink(move |step| {
            assert_eq!(step, FactoryStep::ReadingPackage);
            counter.set(counter.get() + 1);
        }, || {
            report(FactoryStep::ReadingPackage);
            report(FactoryStep::ReadingPackage);
        });
        assert_eq!(seen.get(), 2);
        report(FactoryStep::Publishing);
        assert_eq!(seen.get(), 2);
    }
}
