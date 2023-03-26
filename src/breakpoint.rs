use anyhow::Result;
use nix::{sys::ptrace, unistd::Pid};
use owo_colors::OwoColorize;

const INT3: i64 = 0xcc;

#[derive(Debug)]
pub struct Breakpoint {
    t_pid: nix::unistd::Pid,
    inst_addr: ptrace::AddressType,
    inst_data: Option<u8>,
    enabled: bool,
}

impl Breakpoint {
    pub fn new(t_pid: Pid, inst_addr: ptrace::AddressType) -> Self {
        Self { 
            t_pid, 
            inst_addr, 
            inst_data: None,
            enabled: false, 
        }
    }

    pub fn enable(&mut self) -> Result<()> {
        let data = ptrace::read(self.t_pid, self.inst_addr)?;
        println!("data: {:x?}", data.to_le_bytes().green());
        let data_with_int3 = (data & !0xff) | INT3;
        unsafe { ptrace::write(self.t_pid, self.inst_addr, data_with_int3 as ptrace::AddressType)?; }

        self.inst_data = Some((data & 0xff) as u8);
        self.enabled = true;

        Ok(())
    }

    pub fn disable(&mut self) -> Result<()> {
        let data = ptrace::read(self.t_pid, self.inst_addr)?;
        let orig_data = (data & !0xff) | self.inst_data.unwrap() as i64;
        unsafe { ptrace::write(self.t_pid, self.inst_addr, orig_data as ptrace::AddressType)?; }

        self.inst_data = None; // I don't suppose this is needed
        self.enabled = false;

        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn get_addr(&self) -> ptrace::AddressType {
        self.inst_addr
    }
}