use std::{
    io::{Read, Seek},
    path::Path,
};

use clap::Parser;
use clap_num::maybe_hex;
use pcode_rs::{context::TranslationFlags, language::LanguageDefinitions};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of language
    #[clap(required=true, short, long)]
    id: String,

    /// Path to the binary to translate
    #[clap(required=true, short, long)]
    binary: String,

    /// File offset to start translation
    #[clap(required=true, short, long, value_parser=maybe_hex::<u64>)]
    offset: u64,

    /// Max number of bytes to translate
    #[clap(required=true, short, long, value_parser=maybe_hex::<usize>)]
    num_bytes: usize,

    /// Base address for translation,
    #[clap(required=true, short, long, value_parser=maybe_hex::<u64>)]
    address: u64,

    /// Max number of instructions to translate
    #[clap(short, long, value_parser=maybe_hex::<usize>, default_value_t=0)]
    max_insns: usize,

    flags: Option<u32>,
}

fn main() {
    let args = Args::parse();

    let path: &Path = args.binary.as_ref();
    let file = std::fs::File::open(path).expect("Failed to open file");
    let mut reader = std::io::BufReader::new(file);

    let ldefs = LanguageDefinitions::load().unwrap();
    let mut context = match ldefs.get_context(&args.id) {
        Some(context) => context,
        None => {
            eprintln!("Failed to get context for language: {}", args.id);
            eprintln!("Available languages:",);
            ldefs.into_iter().for_each(|lang| {
                eprintln!("  - {}", lang.id);
            });
            std::process::exit(1);
        }
    };

    let offset = args.offset;
    reader
        .seek(std::io::SeekFrom::Start(offset))
        .expect("Failed to seek to offset");

    let num_bytes = args.num_bytes;
    let mut bytes = vec![0; num_bytes as usize];
    reader.read_exact(&mut bytes).expect("Failed to read bytes");

    let translation = context
        .translate(
            bytes.as_slice(),
            args.address,
            args.max_insns,
            args.flags
                .map(|flag| flag.try_into())
                .unwrap_or(Ok(TranslationFlags::default()))
                .unwrap(),
        )
        .expect("Failed to translate");

    translation.into_iter().for_each(|insn| {
        println!("{}", insn);
    });
}
