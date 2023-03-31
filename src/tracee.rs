use anyhow::Result;
use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use nix::sys::{wait, ptrace, signal::Signal, personality};
use nix::errno::Errno;
use object::Object;
// use std::io::{stdin, Read};
use std::process::Command;
use std::os::unix::process::CommandExt;

use crate::{registers, util};

#[derive(Debug)]
pub struct Tracee {
    pub pid: nix::unistd::Pid,

    elf: object::read::File<'static>,
    endian: gimli::RunTimeEndian,

    pub start_load_addr: u64,
}

impl Tracee {
    pub fn new(path: &str) -> Result<Self> {
        let mut cmd = Command::new(path);
        // cmd
            // .stdout(std::process::Stdio::null())
            // .stderr(std::process::Stdio::null())
            // .arg("/etc/hosts");

        unsafe {
            cmd.pre_exec(|| {
                ptrace::traceme().map_err(<Errno as Into<std::io::Error>>::into)?;

                let pers = personality::get()?;
                _ = personality::set(pers | personality::Persona::ADDR_NO_RANDOMIZE).map_err(<Errno as Into<std::io::Error>>::into)?;

                Ok(())
            });
        }

        let child = cmd.spawn().unwrap();
        let pid = nix::unistd::Pid::from_raw(child.id() as _);

        // It should be okay to use `leak` here as we want the binary data to be present 
        // for the rest of the program
        // so no need to clean it up either
        let bin = std::fs::read(path).unwrap().leak();

        let elf = object::File::parse(&*bin).unwrap();
        let endian = if elf.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        let start_load_addr = if matches!(elf.kind(), object::ObjectKind::Dynamic) {
            let path = format!("/proc/{}/maps", pid);
            // let file = std::fs::File::open(path)?;
            // let first_line = BufReader::new(file).lines().next().expect("maps file can't be empty")?;
            let first_line = util::get_file_lines(path)?.next().expect("maps file can't be empty")?;
            let addr = first_line.split('-').next().expect("maps format not followed");
            u64::from_str_radix(addr, 16)?
        } else {
            0
        };

        let tracee = Self {
            pid,
            elf,
            endian,
            start_load_addr,
        };
        Ok(tracee)
    }

    pub fn wait_for_signal(&self) -> Result<bool> {
        let wait_res = wait::waitpid(self.pid, None).map_err(<Errno as Into<std::io::Error>>::into)?;
        if matches!(wait_res, wait::WaitStatus::Exited(_, _)) {
            Ok(true)
        } else {
            let sig_info = ptrace::getsiginfo(self.pid)?;
            match sig_info.si_signo.try_into()? {
                Signal::SIGTRAP => self.handle_sigtrap(sig_info)?,
                Signal::SIGSEGV => eprintln!("Received SIGSEGV, reason: {:#x}", sig_info.si_code),
                _ => {}
            }
            Ok(false)
        }
    }

    fn handle_sigtrap(&self, sig_info: nix::libc::siginfo_t) -> Result<()> {
        match sig_info.si_code {
            // SI_KERNEL	0x80		/* sent by the kernel from somewhere */
            // TRAP_BRKPT	1	/* process breakpoint */
            0x80 | 0x1 => {
                let pc = registers::get_reg_value(self.pid, registers::Register::Rip)? - 1;
                registers::set_reg_value(self.pid, registers::Register::Rip, pc)?;
                eprintln!("Hit breakpoint at address {:#x}", pc);
                self.print_source(pc)?;
            }
            // TRAP_TRACE	2	/* process trace trap */
            0x2 => eprintln!("Received TRAP_TRACE"),
            // TRAP_BRANCH  3	/* process taken branch trap */
            // TRAP_HWBKPT  4	/* hardware breakpoint/watchpoint */
            // TRAP_UNK	5	/* undiagnosed trap */
            // NSIGTRAP	5
            _ => eprintln!("Received unknown signal code: {:#x}", sig_info.si_code),
        }

        Ok(())
    }

    fn load_dwarf(&self) -> Result<Dwarf<EndianSlice<RunTimeEndian>>, gimli::Error> {
        crate::dwarf::load_dwarf(&self.elf, self.endian)
    }

    fn offset_load_addr(&self, addr: u64) -> u64 {
        addr - self.start_load_addr
    }

    fn print_source(&self, pc: u64) -> Result<()> {
        let offset_pc = self.offset_load_addr(pc);
        if let Some((path, line, _col)) = crate::dwarf::get_line_entry_from_pc(&self.load_dwarf()?, offset_pc)? {
            util::print_source(path.display().to_string(), line, 2)
        } else {
            eprintln!("No source found");
            Ok(())
        }
    }
}