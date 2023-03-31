use anyhow::{Result, anyhow};
use nix::sys::ptrace;
use std::io::{stdin, Read};
use std::collections::HashMap;

use crate::{breakpoint::Breakpoint, registers, tracee::Tracee, util};

pub struct Debugger {
    tracee: Tracee,
    breakpoints: HashMap<ptrace::AddressType, Breakpoint>,
}

impl Debugger {
    pub fn new(path: &str) -> Result<Self> {
        let debugger = Self {  
            tracee: Tracee::new(path)?,
            breakpoints: HashMap::new(),
        };
        Ok(debugger)
    }

    pub fn run(&mut self) -> Result<()> {
        let mut buffer = String::new();
        if self.tracee.wait_for_signal()? { return Ok(()) }
        loop {
            eprint!("> ");
            buffer.clear();
            stdin().read_line(&mut buffer)?;

            let mut split = buffer.trim_end().split(' ');
            match split.next().ok_or(anyhow!("Empty command"))? {
                "b" | "break"             => {
                    let addr = util::parse_hex(split.next().ok_or(anyhow!("No address provided"))?)?;
                    let addr = addr + self.tracee.start_load_addr;
                    self.set_breakpoint_at(addr as ptrace::AddressType)?;
                }
                "c" | "cont" | "continue" => {
                    self.step_over_breakpoint()?;
                    ptrace::cont(self.tracee.pid, None)?;
                    if self.tracee.wait_for_signal()? { break }
                }
                "r" | "reg" | "registers" => {
                    let sc = split.next().ok_or(anyhow!("No subcommand provided"))?;
                    match sc {
                        "d" | "dump" => {
                            let regs = ptrace::getregs(self.tracee.pid)?;
                            println!("REGS: {:?}", regs);
                        }
                        "r" | "read" => {
                            let reg = split.next().ok_or(anyhow!("No register provided"))?;
                            let reg = registers::get_reg_from_string(reg)?;
                            println!("{:#x}", registers::get_reg_value(self.tracee.pid, reg)?);
                        }
                        "w" | "write" => {
                            let reg = split.next().ok_or(anyhow!("No register provided"))?;
                            let reg = registers::get_reg_from_string(reg)?;
                            let value = util::parse_hex(split.next().ok_or(anyhow!("No value provided"))?)?; 
                            registers::set_reg_value(self.tracee.pid, reg, value as u64)?;
                        }
                        _ => return Err(anyhow!("Unknown subcommand: {}", sc)),
                    }
                }
                "m" | "mem" | "memory" => {
                    let sc = split.next().ok_or(anyhow!("No subcommand provided"))?;
                    let addr = util::parse_hex(split.next().ok_or(anyhow!("No address provided"))?)?;
                    match sc {
                        "r" | "read" => {
                            let val = ptrace::read(self.tracee.pid, addr as ptrace::AddressType)?;
                            println!("{:#x}", val);
                        }
                        "w" | "write" => {
                            let val = util::parse_hex(split.next().ok_or(anyhow!("No value provided"))?)?;
                            unsafe { ptrace::write(self.tracee.pid, addr as ptrace::AddressType, val as ptrace::AddressType)?; }
                        }
                        _ => return Err(anyhow!("Unknown subcommand: {}", sc)),
                    }
                }
                cmd => return Err(anyhow!("Empty / Unknown command: {}", cmd)),
            };
        }

        Ok(())
    }
}

impl Debugger {
    fn set_breakpoint_at(&mut self, addr: ptrace::AddressType) -> Result<()> {
        let mut bp = Breakpoint::new(self.tracee.pid, addr);
        bp.enable()?;
        println!("bp: {:?}", bp);
        self.breakpoints.insert(addr, bp);

        Ok(())
    }

    fn step_over_breakpoint(&mut self) -> Result<()> {
        // let pc = registers::get_reg_value(self.pid, registers::Register::Rip)? - 1;
        let pc = registers::get_reg_value(self.tracee.pid, registers::Register::Rip)?;
        if let Some(bp) = self.breakpoints.get_mut(&(pc as ptrace::AddressType)) && bp.is_enabled() {
            eprintln!("step over breakpoint");
            bp.disable()?;
            // registers::set_reg_value(self.pid, registers::Register::Rip, pc)?;
            ptrace::step(self.tracee.pid, None)?;
            self.tracee.wait_for_signal()?;
            bp.enable()?;
        }

        Ok(())
    }
}
