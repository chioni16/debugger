use anyhow::{anyhow, Result};
use nix::libc;
use nix::sys::ptrace;
use nix::unistd::Pid;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Register {
    Rax,
    Rbx,
    Rcx,
    Rdx,

    Rdi,
    Rsi,
    Rbp,
    Rsp,

    R8,
    R9,
    R10,
    R11,

    R12,
    R13,
    R14,
    R15,

    Rip,
    Rflags,
    Cs,

    OrigRax,
    FsBase,
    GsBase,

    Fs,
    Gs,
    Ss,
    Ds,
    Es,
}

pub fn get_reg_value(pid: Pid, reg: Register) -> Result<u64> {
    let regs = ptrace::getregs(pid)?;
    let value = *get_reg(&regs, reg);
    Ok(value)
}

pub fn set_reg_value(pid: Pid, reg: Register, value: u64) -> Result<()> {
    let mut regs = ptrace::getregs(pid)?;
    let reg = get_mutable_reg(&mut regs, reg);
    *reg = value;
    ptrace::setregs(pid, regs)?;
    Ok(())
}

pub fn get_reg_from_string(s: &str) -> Result<Register> {
    let reg = match s.to_ascii_lowercase().as_str() {
        "rax" => Register::Rax,
        "rbx" => Register::Rbx,
        "rcx" => Register::Rcx,
        "rdx" => Register::Rdx,

        "rdi" => Register::Rdi,
        "rsi" => Register::Rsi,
        "rbp" => Register::Rbp,
        "rsp" => Register::Rsp,

        "r8" => Register::R8,
        "r9" => Register::R9,
        "r10" => Register::R10,
        "r11" => Register::R11,

        "r12" => Register::R12,
        "r13" => Register::R13,
        "r14" => Register::R14,
        "r15" => Register::R15,

        "rip" => Register::Rip,
        "rflags" => Register::Rflags,
        "cs" => Register::Cs,

        "orig_rax" => Register::OrigRax,
        "fs_base" => Register::FsBase,
        "gs_base" => Register::GsBase,

        "fs" => Register::Fs,
        "gs" => Register::Gs,
        "ss" => Register::Ss,
        "ds" => Register::Ds,
        "es" => Register::Es,

        _ => return Err(anyhow!("Unrecognised register: {}", s)),
    };

    Ok(reg)
}

pub fn get_dwarf_number_from_reg(reg: Register) -> Option<u8> {
    let dwarf = match reg {
        Register::Rax => 0,
        Register::Rbx => 3,
        Register::Rcx => 2,
        Register::Rdx => 1,

        Register::Rdi => 5,
        Register::Rsi => 4,
        Register::Rbp => 6,
        Register::Rsp => 7,

        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,

        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,

        Register::Rflags => 49,
        Register::Cs => 51,

        Register::FsBase => 58,
        Register::GsBase => 59,

        Register::Fs => 54,
        Register::Gs => 55,
        Register::Ss => 52,
        Register::Ds => 53,
        Register::Es => 50,

        Register::Rip | Register::OrigRax => return None,
    };
    Some(dwarf)
}

pub fn get_reg_from_dwarf_number(dwarf: u8) -> Result<Register> {
    let reg = match dwarf {
        0 => Register::Rax,
        3 => Register::Rbx,
        2 => Register::Rcx,
        1 => Register::Rdx,

        5 => Register::Rdi,
        4 => Register::Rsi,
        6 => Register::Rbp,
        7 => Register::Rsp,

        8 => Register::R8,
        9 => Register::R9,
        10 => Register::R10,
        11 => Register::R11,

        12 => Register::R12,
        13 => Register::R13,
        14 => Register::R14,
        15 => Register::R15,

        // Register::Rip = 255,
        49 => Register::Rflags,
        51 => Register::Cs,

        // Register::OrigRax = 244,
        58 => Register::FsBase,
        59 => Register::GsBase,

        54 => Register::Fs,
        55 => Register::Gs,
        52 => Register::Ss,
        53 => Register::Ds,
        50 => Register::Es,

        _ => {
            return Err(anyhow!(
                "Received unsupported dwarf register number: {}",
                dwarf
            ))
        }
    };
    Ok(reg)
}

fn get_reg(regs: &libc::user_regs_struct, reg: Register) -> &libc::c_ulonglong {
    match reg {
        Register::Rax => &regs.rax,
        Register::Rbx => &regs.rbx,
        Register::Rcx => &regs.rcx,
        Register::Rdx => &regs.rdx,

        Register::Rdi => &regs.rdi,
        Register::Rsi => &regs.rsi,
        Register::Rbp => &regs.rbp,
        Register::Rsp => &regs.rsp,

        Register::R8 => &regs.r8,
        Register::R9 => &regs.r9,
        Register::R10 => &regs.r10,
        Register::R11 => &regs.r11,

        Register::R12 => &regs.r12,
        Register::R13 => &regs.r13,
        Register::R14 => &regs.r14,
        Register::R15 => &regs.r15,

        Register::Rip => &regs.rip,
        Register::Rflags => &regs.eflags,
        Register::Cs => &regs.cs,

        Register::OrigRax => &regs.orig_rax,
        Register::FsBase => &regs.fs_base,

        Register::GsBase => &regs.gs_base,

        Register::Fs => &regs.fs,
        Register::Gs => &regs.gs,
        Register::Ss => &regs.ss,
        Register::Ds => &regs.ds,
        Register::Es => &regs.es,
    }
}

fn get_mutable_reg(regs: &mut libc::user_regs_struct, reg: Register) -> &mut libc::c_ulonglong {
    match reg {
        Register::Rax => &mut regs.rax,
        Register::Rbx => &mut regs.rbx,
        Register::Rcx => &mut regs.rcx,
        Register::Rdx => &mut regs.rdx,

        Register::Rdi => &mut regs.rdi,
        Register::Rsi => &mut regs.rsi,
        Register::Rbp => &mut regs.rbp,
        Register::Rsp => &mut regs.rsp,

        Register::R8 => &mut regs.r8,
        Register::R9 => &mut regs.r9,
        Register::R10 => &mut regs.r10,
        Register::R11 => &mut regs.r11,

        Register::R12 => &mut regs.r12,
        Register::R13 => &mut regs.r13,
        Register::R14 => &mut regs.r14,
        Register::R15 => &mut regs.r15,

        Register::Rip => &mut regs.rip,
        Register::Rflags => &mut regs.eflags,
        Register::Cs => &mut regs.cs,

        Register::OrigRax => &mut regs.orig_rax,
        Register::FsBase => &mut regs.fs_base,

        Register::GsBase => &mut regs.gs_base,

        Register::Fs => &mut regs.fs,
        Register::Gs => &mut regs.gs,
        Register::Ss => &mut regs.ss,
        Register::Ds => &mut regs.ds,
        Register::Es => &mut regs.es,
    }
}
