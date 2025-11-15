use crate::wasi::clocks::wall_clock::{Datetime, now};

pub trait TaskStorage<S> {
    type Error;
    async fn initialize(name: &str) -> Result<Datetime, Self::Error>;
    async fn update(name: &str, state: &S) -> Result<(), Self::Error>;
    async fn restore(name: &str) -> Result<Option<(Datetime, S)>, Self::Error>;
}

pub struct NoStore;
impl<S> TaskStorage<S> for NoStore {
    type Error = ();
    async fn initialize(_name: &str) -> Result<Datetime, Self::Error> {
        Ok(now())
    }
    async fn update(_name: &str, _state: &S) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn restore(_name: &str) -> Result<Option<(Datetime, S)>, Self::Error> {
        Ok(None)
    }
}
