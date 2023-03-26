#![feature(let_chains)]

mod breakpoint;
mod debugger;
mod registers;

use std::{process::{Command, Stdio}, os::unix::process::CommandExt};
use anyhow::Result;
use debugger::Debugger;
use nix::{sys::{ptrace, personality}, errno::Errno};

fn main() -> Result<()> {
    let mut cmd = Command::new("/home/govardhan/projects/debugger/target/test");
    // cmd
        // .stdout(Stdio::null())
        // .stderr(Stdio::null())
        // .arg("/etc/hosts");

    unsafe {
        cmd.pre_exec(|| {
            ptrace::traceme().map_err(<Errno as Into<std::io::Error>>::into)?;

            let pers = personality::get()?;
            _ = personality::set(pers | personality::Persona::ADDR_NO_RANDOMIZE).map_err(<Errno as Into<std::io::Error>>::into)?;

            Ok(())
        });
    }

    let child = cmd.spawn()?;
    let child_pid = nix::unistd::Pid::from_raw(child.id() as _);

    let mut debugger = Debugger::new(child_pid);
    debugger.run()

}
