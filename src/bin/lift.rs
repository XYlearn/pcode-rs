use std::{
    io::{Read, Seek},
    path::Path,
};

use clap::Parser;
use clap_num::maybe_hex;
use pcode_rs::{
    anal::lift::Lifter,
    sleigh::{LanguageDefinitions, TranslationFlags},
};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of language
    #[clap(required = true, short, long)]
    id: String,

    /// Path to the binary to translate
    #[clap(required = true, short, long)]
    binary: String,

    /// File offset to start translation
    #[clap(required=true, short, long, value_parser=maybe_hex::<u64>)]
    offset: u64,

    /// Base address for translation,
    #[clap(required=true, short, long, value_parser=maybe_hex::<u64>)]
    address: u64,
}

fn main() {
    let args = Args::parse();

    let path: &Path = args.binary.as_ref();
    let file = std::fs::File::open(path).expect("Failed to open file");
    let reader = std::io::BufReader::new(file);

    let ldefs = LanguageDefinitions::load().unwrap();
    let context = match ldefs.get_context(&args.id) {
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

    let mut lifter = Lifter::new(context, reader);
    lifter
        .lift(args.address, args.offset)
        .expect("Failed to lift");
}
