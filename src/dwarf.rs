use std::{ops::Range, path::PathBuf};
use std::path;

use gimli::{Dwarf, EndianSlice, RunTimeEndian, read::{Unit, UnitOffset, DebuggingInformationEntry}};
use object::{Object, ObjectSection};
use anyhow::Result;

// #[allow(unused)]
// pub fn runner() {
//     let path = "target/test";
//     let bin = std::fs::read(path).unwrap();
//     let object = object::File::parse(&*bin).unwrap();
//     let endian = if object.is_little_endian() {
//         gimli::RunTimeEndian::Little
//     } else {
//         gimli::RunTimeEndian::Big
//     };
//     let dwarf = load_dwarf(&object, endian).unwrap();
//     let (unit, offset) = get_function_from_pc(&dwarf, 0x1150).unwrap().unwrap();
//     let entry = unit.entry(offset).unwrap();
//     println!("<{:x}> {}", entry.offset().0, entry.tag());
//     print_die_attrs(&entry).unwrap();
//     println!("line entry from pc: {:x?}", get_line_entry_from_pc(&dwarf, 0x1150).unwrap());
// }

pub(crate) fn load_dwarf<'o>(object: &'o object::File<'o>, endian: gimli::RunTimeEndian) -> Result<Dwarf<EndianSlice<'o, RunTimeEndian>>, gimli::Error> {
// pub(crate) fn load_dwarf<'o, R: gimli::Reader>(object: &'o object::File<'o>, endian: gimli::RunTimeEndian) -> Result<Dwarf<impl gimli::Reader + 'o>, gimli::Error> {
    let load_section = |id: gimli::SectionId| -> Result<gimli::EndianSlice<RunTimeEndian>, gimli::Error> {
        match object.section_by_name(id.name()) {
            Some(ref section) => {
                let section = section
                .data()
                .unwrap_or(&[][..]);
                let section = gimli::EndianSlice::new(section, endian);
                Ok(section)
            }
            None => {
                let section = &[][..];
                let section = gimli::EndianSlice::new(&*section, endian);
                Ok(section)
            }
        }
    };

    let d = gimli::Dwarf::load(&load_section)?;
    Ok(d)
}

// pub fn get_function_from_pc<R: gimli::Reader>(dwarf: &Dwarf<R>, pc: u64) -> Result<Option<(Unit<R, <R as gimli::Reader>::Offset>, UnitOffset<<R as gimli::Reader>::Offset>)>> {
pub fn get_function_from_pc<R: gimli::Reader>(dwarf: &Dwarf<R>, pc: u64) -> Result<Option<(Unit<R>, UnitOffset<<R as gimli::Reader>::Offset>)>> {
    if let Some(unit) = get_compile_unit_for_pc(dwarf, pc)? {
        let mut depth = 0; 

        let mut entries = unit.entries();
        while let Some((delta_depth, entry)) = entries.next_dfs()? {
            depth += delta_depth;
            if matches!(entry.tag(), gimli::DW_TAG_subprogram) && get_die_addr_range(entry)?.contains(&pc) { 
                let offset =  entry.offset().to_owned();
                // return Ok(Some((unit, offset)))
                return Ok(Some(()))
            }
        }
    }

    Ok(None)
}

pub fn get_line_entry_from_pc<R: gimli::Reader>(dwarf: &Dwarf<R>, pc: u64) -> Result<Option<LineEntry>> {
    let mut value = None;

    if let Some(unit) = get_compile_unit_for_pc(dwarf, pc)? 
    && let Some(program) = unit.line_program.clone()
    {
        let comp_dir = if let Some(ref dir) = unit.comp_dir {
            path::PathBuf::from(dir.to_string_lossy()?.into_owned())
        } else {
            path::PathBuf::new()
        };

        let mut rows = program.rows();
        while let Some((header, row)) = rows.next_row()? && row.address() < pc{
            // Determine the path. Real applications should cache this for performance.
            let mut path = path::PathBuf::new();
            if let Some(file) = row.file(header) {
                path = comp_dir.clone();

                // The directory index 0 is defined to correspond to the compilation unit directory.
                if file.directory_index() != 0 {
                    if let Some(dir) = file.directory(header) {
                        path.push(
                            dwarf.attr_string(&unit, dir)?.to_string_lossy()?.as_ref(),
                        );
                    }
                }

                path.push(
                    dwarf
                        .attr_string(&unit, file.path_name())?
                        .to_string_lossy()?
                        .as_ref(),
                );
            }

            // Determine line/column. DWARF line/column is never 0, so we use that
            // but other applications may want to display this differently.
            let line = match row.line() {
                Some(line) => line.get(),
                None => 0,
            } as usize;
            let col = match row.column() {
                gimli::ColumnType::LeftEdge => 0,
                gimli::ColumnType::Column(column) => column.get(),
            } as usize;

            value = Some(LineEntry {
                path, 
                line, 
                col,
            });
        }
    }

    Ok(value)
}

pub fn get_compile_unit_for_pc<R: gimli::Reader>(dwarf: &Dwarf<R>, pc: u64) -> Result<Option<gimli::Unit<R>>> {
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();

        if let Some((_, cu)) = entries.next_dfs()? 
        && matches!(cu.tag(), gimli::DW_TAG_compile_unit) 
        && get_die_addr_range(cu)?.contains(&pc)
        {
            return Ok(Some(unit)); 
        }
    }
    Ok(None)
}

fn get_die_addr_range<R: gimli::Reader>(entry: &DebuggingInformationEntry<R>) -> Result<Range<u64>> {
    let gimli::AttributeValue::Addr(low_pc)   = entry.attr_value(gimli::DW_AT_low_pc)?.unwrap() else {unreachable!()};
    let gimli::AttributeValue::Udata(high_pc) = entry.attr_value(gimli::DW_AT_high_pc)?.unwrap() else {unreachable!()};
    Ok(low_pc..low_pc+high_pc)
}

fn print_die_attrs<R: gimli::Reader>(entry: &DebuggingInformationEntry<R>) -> Result<()> {
    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next()? {
        println!("   {}: {:x?}", attr.name(), attr.value());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct LineEntry {
    pub path: PathBuf,
    pub line: usize,
    pub col: usize,
}