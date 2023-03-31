#![feature(let_chains)]
#![feature(trivial_bounds)]

mod breakpoint;
mod dwarf;
mod debugger;
mod registers;
mod tracee;
mod util;

use anyhow::Result;
use debugger::Debugger;

fn main() -> Result<()> {
    let path = "/home/govardhan/projects/debugger/target/test";
    let mut debugger = Debugger::new(path)?;
    debugger.run()
}
