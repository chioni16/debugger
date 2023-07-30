use anyhow::{anyhow, Result};
use nix::sys::ptrace;
use std::collections::HashMap;
use std::io::stdin;

use crate::{
    breakpoint::{Breakpoint, BreakpointLaterAction},
    dwarf, registers,
    tracee::Tracee,
    util,
};

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
        if self.tracee.wait_for_signal()? {
            return Ok(());
        }
        loop {
            eprint!("> ");
            buffer.clear();
            stdin().read_line(&mut buffer)?;

            let mut split = buffer.trim_end().split(' ');
            match split.next().ok_or(anyhow!("Empty command"))? {
                "b" | "break" => {
                    let addr =
                        util::parse_hex(split.next().ok_or(anyhow!("No address provided"))?)?;
                    // let addr = addr + self.tracee.start_load_addr;
                    let addr = self.tracee.add_load_addr(addr);
                    self.set_breakpoint_at(addr as ptrace::AddressType)?;
                }
                "c" | "cont" | "continue" => {
                    if self.continue_execution()? {
                        break;
                    }
                }
                "si" | "stepi" => self.single_step_instr_with_breakpoint_check()?,
                "step" => self.step_in()?,
                "next" => self.step_over()?,
                "finish" => self.step_out()?,
                "r" | "reg" | "registers" => {
                    let sc = split.next().ok_or(anyhow!("No subcommand provided"))?;
                    match sc {
                        "d" | "dump" => {
                            let regs = ptrace::getregs(self.tracee.pid)?;
                            println!("REGS: {:#x?}", regs);
                        }
                        "r" | "read" => {
                            let reg = split.next().ok_or(anyhow!("No register provided"))?;
                            let reg = registers::get_reg_from_string(reg)?;
                            println!("{:#x}", registers::get_reg_value(self.tracee.pid, reg)?);
                        }
                        "w" | "write" => {
                            let reg = split.next().ok_or(anyhow!("No register provided"))?;
                            let reg = registers::get_reg_from_string(reg)?;
                            let value =
                                util::parse_hex(split.next().ok_or(anyhow!("No value provided"))?)?;
                            registers::set_reg_value(self.tracee.pid, reg, value as u64)?;
                        }
                        _ => return Err(anyhow!("Unknown subcommand: {}", sc)),
                    }
                }
                "m" | "mem" | "memory" => {
                    let sc = split.next().ok_or(anyhow!("No subcommand provided"))?;
                    let addr =
                        util::parse_hex(split.next().ok_or(anyhow!("No address provided"))?)?;
                    match sc {
                        "r" | "read" => {
                            let val = self.tracee.read_mem(addr)?;
                            // ptrace::read(self.tracee.pid, addr as ptrace::AddressType)?;
                            println!("{:#x}", val);
                        }
                        "w" | "write" => {
                            let val =
                                util::parse_hex(split.next().ok_or(anyhow!("No value provided"))?)?;
                            self.tracee.write_mem(addr, val)?;
                            // unsafe { ptrace::write(self.tracee.pid, addr as ptrace::AddressType, val as ptrace::AddressType)?; }
                        }
                        _ => return Err(anyhow!("Unknown subcommand: {}", sc)),
                    }
                }
                "l" | "lines" => self.tracee.print_source()?,
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

    fn set_temp_breakpoint_at(
        &mut self,
        addr: ptrace::AddressType,
    ) -> Result<BreakpointLaterAction> {
        let la = if let Some(bp) = self.breakpoints.get_mut(&addr) {
            if bp.is_enabled() {
                BreakpointLaterAction::Nothing
            } else {
                bp.enable()?;
                BreakpointLaterAction::Disable
            }
        } else {
            self.set_breakpoint_at(addr)?;
            BreakpointLaterAction::Delete
        };
        Ok(la)
    }

    fn step_over_breakpoint(&mut self) -> Result<bool> {
        let mut bp_present = false;
        // let pc = registers::get_reg_value(self.pid, registers::Register::Rip)? - 1;
        let pc = registers::get_reg_value(self.tracee.pid, registers::Register::Rip)?;
        if let Some(bp) = self.breakpoints.get_mut(&(pc as ptrace::AddressType)) && bp.is_enabled() {
            eprintln!("step over breakpoint");
            bp.disable()?;
            // registers::set_reg_value(self.pid, registers::Register::Rip, pc)?;
            self.tracee.single_step_instr()?;
            // ptrace::step(self.tracee.pid, None)?;
            // self.tracee.wait_for_signal()?;
            bp.enable()?;

            bp_present = true;
        }

        Ok(bp_present)
    }

    fn single_step_instr_with_breakpoint_check(&mut self) -> Result<()> {
        if !self.step_over_breakpoint()? {
            self.tracee.single_step_instr()?;
        }

        Ok(())
    }

    // The return value specifies if the tracee has exited or not
    // true => tracee has exited
    // false => tracee is still alive
    fn continue_execution(&mut self) -> Result<bool> {
        self.step_over_breakpoint()?;
        ptrace::cont(self.tracee.pid, None)?;
        self.tracee.wait_for_signal()
    }

    fn step_in(&mut self) -> Result<()> {
        let start_line_entry = self.tracee.get_line_entry()?;
        while self.tracee.get_line_entry()? == start_line_entry {
            self.single_step_instr_with_breakpoint_check()?;
        }
        Ok(())
    }

    fn step_out(&mut self) -> Result<()> {
        let fp = registers::get_reg_value(self.tracee.pid, registers::Register::Rbp)?;
        let ret_addr = ptrace::read(self.tracee.pid, (fp + 8) as ptrace::AddressType)?;

        let la = self.set_temp_breakpoint_at(ret_addr as ptrace::AddressType)?;

        self.continue_execution()?;

        self.reverse_breakpoint(ret_addr as ptrace::AddressType, la)?;

        Ok(())
    }

    fn step_over(&mut self) -> Result<()> {
        println!("start of step over");
        let (unit, offset) = self
            .tracee
            .get_func()?
            .ok_or(anyhow!("Currently not in a function defined in the binary"))?;
        let func = unit.entry(offset)?;
        println!("found function");

        let func_range = dwarf::get_die_addr_range(&func)?;
        let func_start_line =
            dwarf::get_line_entry_from_pc(&self.tracee.load_dwarf()?, func_range.start)?
                .ok_or(anyhow!("Func start not found"))?;
        let func_end_line =
            dwarf::get_line_entry_from_pc(&self.tracee.load_dwarf()?, func_range.end)?
                .ok_or(anyhow!("Func end not found"))?;
        let start_line = self
            .tracee
            .get_line_entry()?
            .ok_or(anyhow!("Start line not found"))?;
        println!("found function lines:\nfunc_start_line: {:#?}\nfunc_end_line: {:#?}\nstart_line: {:#?}\n", func_start_line, func_end_line, start_line);

        let lines = dwarf::get_lines_for_unit(&unit)?;
        println!("lines: {:#?}", lines);
        let mut addrs = (func_start_line.line..=func_end_line.line)
            .into_iter()
            .filter(|line_no| *line_no != start_line.line)
            .filter_map(|ref line_no| {
                println!("line_no: {}", line_no);
                lines.get(line_no)
                .map(|addr| {
                    let addr = self.tracee.add_load_addr(*addr as u64) as ptrace::AddressType;
                    self.set_temp_breakpoint_at(addr).map(|la| (addr, la))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        println!("addrs: {:#?}", addrs);

        let fp = registers::get_reg_value(self.tracee.pid, registers::Register::Rbp)?;
        let ret_addr = ptrace::read(self.tracee.pid, (fp + 8) as ptrace::AddressType)?;
        let rla = self.set_temp_breakpoint_at(ret_addr as ptrace::AddressType)?;
        addrs.push((ret_addr as ptrace::AddressType, rla));

        self.continue_execution()?;

        for (addr, la) in addrs {
            self.reverse_breakpoint(addr, la)?;
        }

        Ok(())
    }

    fn reverse_breakpoint(
        &mut self,
        key: ptrace::AddressType,
        action: BreakpointLaterAction,
    ) -> Result<()> {
        match action {
            BreakpointLaterAction::Nothing => {}
            BreakpointLaterAction::Delete => {
                let mut bp = self.breakpoints.remove(&key).unwrap();
                bp.disable()?;
            }
            BreakpointLaterAction::Disable => {
                let bp = self.breakpoints.get_mut(&key).unwrap();
                bp.disable()?;
            }
            BreakpointLaterAction::Enable => {
                let bp = self.breakpoints.get_mut(&key).unwrap();
                bp.enable()?;
            }
        };

        Ok(())
    }
}
