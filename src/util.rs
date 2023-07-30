use anyhow::{anyhow, Result};
use std::io::{BufRead, BufReader};

pub fn parse_hex(val: &str) -> Result<u64> {
    if &val[..2] != "0x" {
        return Err(anyhow!("Pass hexadecimal values starting with 0x"));
    }
    let val = u64::from_str_radix(&val[2..], 16)?;
    Ok(val)
}

pub fn print_source(path: impl AsRef<str>, n_line: usize, n_lines_context: usize) -> Result<()> {
    let start = if n_line <= n_lines_context {
        1
    } else {
        n_line - n_lines_context
    };
    let end = n_line
        + n_lines_context
        + if n_line < n_lines_context {
            n_lines_context - n_line
        } else {
            0
        }
        + 1;

    for (i, line) in get_file_lines(path.as_ref())?.enumerate() {
        if i < start {
            continue;
        }
        if i > end {
            break;
        }
        eprint!("{}", if i == n_line { "> " } else { "  " });
        eprintln!("{}", line?);
    }

    Ok(())
}

pub fn get_file_lines(path: impl AsRef<str>) -> Result<std::io::Lines<BufReader<std::fs::File>>> {
    let file = std::fs::File::open(path.as_ref())?;
    Ok(BufReader::new(file).lines())
}
