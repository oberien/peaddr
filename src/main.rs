extern crate goblin;
extern crate pdb;

use std::env;
use std::fs::File;
use std::io::Read;
use std::ffi::CStr;

use goblin::Object;
use pdb::{PDB, SymbolData};
use pdb::FallibleIterator;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <exe> <pdb>", args[0]);
    }
    let exe = &args[1];
    let pdb = &args[2];
    let mut exe = File::open(exe.as_str()).expect("Couldn't open exe");
    let pdb = File::open(pdb.as_str()).expect("Couldn't open pdb");
    let mut binary = Vec::new();
    exe.read_to_end(&mut binary).unwrap();
    let pe = match Object::parse(&binary).expect("Couldn't parse exe") {
        Object::PE(pe) => pe,
        _ => panic!("Exe is not a PE")
    };

    let mut pdb = PDB::open(&pdb).expect("Couldn't read pdb");
    let table = pdb.global_symbols().expect("Couldn't find global symbol table");
    let mut iter = table.iter();
    while let Some(symbol) = iter.next().expect("Error getting next symbol") {
        let symbol_data = symbol.parse().expect("Error parsing symbol");

        let (segment, offset, typ) = match symbol_data {
            SymbolData::PublicSymbol { function: true, segment, offset, .. } => (segment, offset, "function"),
            SymbolData::DataSymbol { segment, offset, .. } => (segment, offset, "data"),
            _ => continue
        };
        let name = match symbol.name() {
            Ok(name) => name,
            Err(e) => {
                eprintln!("Error getting symbol name: {}", e);
                continue
            }
        };

        match pe.sections.get((segment as usize).wrapping_sub(1)) {
            Some(section) => {
                let section_name = String::from_utf8_lossy(&section.name.split(|b| *b == 0).next().unwrap());
                let section_va = section.virtual_address;
                println!("{:8} {:8x}    {:10} {}", section_name, section_va + offset, typ, name);
            },
            None => {
                println!("{:8} {:8}    {:10} {}", "-", "-", typ, name);
            }
        }
    }
}
