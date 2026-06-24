mod error;
pub use error::*;
mod constants;
pub use constants::*;

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
pub use client::*;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
pub use server::*;

pub type DoCanResult<R> = Result<R, DoCanError>;
