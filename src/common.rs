use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct Properties {
    pub property: Vec<Property>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Property {
    #[serde(rename = "@key")]
    key: String,
    #[serde(rename = "@value")]
    value: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "@space")]
    space: String,
    #[serde(default, rename = "@first")]
    first: Option<String>,
    #[serde(default, rename = "@last")]
    last: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextData {
    #[serde(default)]
    pub context_set: Vec<ContextTrackedSet>,
    #[serde(default)]
    pub tracked_set: Vec<ContextTrackedSet>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextTrackedSet {
    #[serde(rename = "@space")]
    pub space: String,
    #[serde(default, rename = "@first")]
    pub first: Option<String>,
    #[serde(default, rename = "@last")]
    pub last: Option<String>,
    pub set: Vec<ContextTrackedSetData>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextTrackedSetData {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@val")]
    pub val: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use quick_xml::de;

    #[test]
    fn test() {
        let s = r#"
        <properties>
        <property key="useOperandReferenceAnalyzerSwitchTables" value="true"/>
        <property key="assemblyRating:x86:LE:64:default" value="GOLD"/>
        </properties>
        "#;
        let props: Result<Properties, de::DeError> = de::from_str(s);
        assert!(props.is_ok(), "Failed to parse properties: {:?}", props);
        let props = props.unwrap();
        assert_eq!(props.property.len(), 2);
    }
}
