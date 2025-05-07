use std::io::BufReader;
use std::task::Context;
use std::{fs::File, path::Path};

use super::common::{ContextData, Range};

use super::common::Properties;
use anyhow::Result;
use quick_xml::de;
use serde::{Deserialize, Serialize};

/// Processor Specification
/// Reference: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/SoftwareModeling/data/languages/processor_spec.rxg
/// TODO: many fields are not implemented yet
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProcessorSpec {
    #[serde(default)]
    pub properties: Properties,
    #[serde(default)]
    pub programcounter: Option<ProgramCounter>,
    pub data_space: Option<DataSpace>,
    pub inferptrbounds: Option<Vec<InferPtrBounds>>,
    pub context_data: Option<ContextData>,
}

impl ProcessorSpec {
    pub fn load(path: impl AsRef<Path>) -> Result<ProcessorSpec> {
        let file = File::open(path)?;
        let buf_reader = BufReader::new(file); // Buffering is important for performance

        Ok(de::from_reader(buf_reader)?)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ProgramCounter {
    #[serde(rename = "@register")]
    pub register: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DataSpace {
    #[serde(rename = "@space")]
    pub space: String,
    #[serde(default, rename = "@ptr_wordsize")]
    pub ptr_wordsize: Option<u32>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InferPtrBounds {
    pub range: Vec<Range>,
}

#[cfg(test)]
mod test {
    use crate::sleigh::LanguageDefinitions;

    use super::*;

    #[test]
    fn test_load_processor_spec() {
        LanguageDefinitions::load()
            .unwrap()
            .into_iter()
            .for_each(|ldef| {
                let data_dir: &Path = ldef.data_dir.as_ref();
                let processor_spec_path = data_dir.join(&ldef.processorspec);
                let processor_spec = ProcessorSpec::load(processor_spec_path);
                assert!(
                    processor_spec.is_ok(),
                    "Failed to load processor spec: {:?}",
                    processor_spec
                );
            });
    }
}
