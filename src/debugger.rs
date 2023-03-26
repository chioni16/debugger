use anyhow::{Result, anyhow};
use nix::sys::{wait, ptrace};
use std::{io::stdin, collections::HashMap};

use crate::{breakpoint::Breakpoint, registers};

pub struct Debugger {
    t_pid: nix::unistd::Pid,
    breakpoints: HashMap<ptrace::AddressType, Breakpoint>,
}

impl Debugger {
    pub fn new(t_pid: nix::unistd::Pid) -> Self {
        Self {  
            t_pid,
            breakpoints: HashMap::new(),
        }
    }

    pub fn set_breakpoint_at(&mut self, addr: ptrace::AddressType) -> Result<()> {
        let mut bp = Breakpoint::new(self.t_pid, addr);
        bp.enable()?;

        self.breakpoints.insert(addr, bp);

        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let mut buffer = String::new();
        if matches!(wait::waitpid(self.t_pid, None)?, wait::WaitStatus::Exited(_, _)) {
            return Ok(());
        }
        loop {
            eprint!("> ");
            buffer.clear();
            stdin().read_line(&mut buffer)?;

            let mut split = buffer.trim_end().split(' ');
            match split.next().ok_or(anyhow!("Empty command"))? {
                "b" | "break"             => {
                    let addr = parse_hex(split.next().ok_or(anyhow!("No address provided"))?)?;
                    self.set_breakpoint_at(addr as ptrace::AddressType)?;
                }
                "c" | "cont" | "continue" => {
                    self.step_over_breakpoint()?;
                    ptrace::cont(self.t_pid, None)?;
                    if matches!(wait::waitpid(self.t_pid, None)?, wait::WaitStatus::Exited(_, _)) {
                        break;
                    }
                }
                "r" | "reg" | "registers" => {
                    let sc = split.next().ok_or(anyhow!("No subcommand provided"))?;
                    match sc {
                        "dump" => {
                            let regs = ptrace::getregs(self.t_pid)?;
                            println!("REGS: {:?}", regs);
                        }
                        "read" => {
                            let reg = split.next().ok_or(anyhow!("No register provided"))?;
                            let reg = registers::get_reg_from_string(reg)?;
                            println!("{:#x}", registers::get_reg_value(self.t_pid, reg)?);
                        }
                        "write" => {
                            let reg = split.next().ok_or(anyhow!("No register provided"))?;
                            let reg = registers::get_reg_from_string(reg)?;
                            let value = parse_hex(split.next().ok_or(anyhow!("No value provided"))?)?; 
                            registers::set_reg_value(self.t_pid, reg, value as u64)?;
                        }
                        _ => return Err(anyhow!("Unknown subcommand: {}", sc)),
                    }
                }
                "m" | "mem" | "memory" => {
                    let sc = split.next().ok_or(anyhow!("No subcommand provided"))?;
                    let addr = parse_hex(split.next().ok_or(anyhow!("No address provided"))?)?;
                    match sc {
                        "read" => {
                            let val = ptrace::read(self.t_pid, addr as ptrace::AddressType)?;
                            println!("{:#x}", val);
                        }
                        "write" => {
                            let val = parse_hex(split.next().ok_or(anyhow!("No value provided"))?)?;
                            unsafe { ptrace::write(self.t_pid, addr as ptrace::AddressType, val as ptrace::AddressType)?; }
                        }
                        _ => return Err(anyhow!("Unknown subcommand: {}", sc)),
                    }
                }
                cmd => return Err(anyhow!("Empty / Unknown command: {}", cmd)),
            };
        }

        Ok(())
    }

    fn step_over_breakpoint(&mut self) -> Result<()> {
        let pc = registers::get_reg_value(self.t_pid, registers::Register::Rip)? - 1;
        if let Some(bp) = self.breakpoints.get_mut(&(pc as ptrace::AddressType)) && bp.is_enabled() {
            eprintln!("step over breakpoint");
            bp.disable()?;
            registers::set_reg_value(self.t_pid, registers::Register::Rip, pc)?;
            ptrace::step(self.t_pid, None)?;
            wait::waitpid(self.t_pid, None)?;
            bp.enable()?;
        }

        Ok(())
    }

}

fn parse_hex(val: &str) -> Result<i64> {
    if &val[..2] != "0x" {
        return Err(anyhow!("Pass hexadecimal values starting with 0x"));
    }
    let val = i64::from_str_radix(&val[2..], 16)?;
    Ok(val)
}