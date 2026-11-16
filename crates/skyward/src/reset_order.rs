//! Factory-reset destructive stages. All non-destructive preflight and closing
//! of data must finish before this sequence starts. Never continue on error.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Part { Metadata, Data, Cache }
pub fn parts(cache:bool)->Vec<Part> {
 let mut parts=vec![Part::Metadata,Part::Data];if cache {parts.push(Part::Cache)}parts
}
pub fn run<E>(cache:bool,mut work:impl FnMut(Part)->Result<(),E>)->Result<(),(Part,E)> {
 for part in parts(cache) {work(part).map_err(|error|(part,error))?;}Ok(())
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn metadata_then_data_then_optional_cache(){assert_eq!(parts(false),[Part::Metadata,Part::Data]);assert_eq!(parts(true),[Part::Metadata,Part::Data,Part::Cache]);}
 #[test]fn metadata_failure_cannot_touch_data(){let mut called=Vec::new();let failed=run(true,|part|{called.push(part);Err("formatter failed")});assert_eq!(called,[Part::Metadata]);assert_eq!(failed,Err((Part::Metadata,"formatter failed")));}
 #[test]fn data_failure_cannot_touch_cache_or_report_success(){let mut called=Vec::new();let failed=run(true,|part|{called.push(part);if part==Part::Data{Err("data format failed")}else{Ok(())}});assert_eq!(called,[Part::Metadata,Part::Data]);assert_eq!(failed,Err((Part::Data,"data format failed")));}
 #[test]fn success_completes_every_selected_stage(){let mut called=Vec::new();let result:Result<(),(Part,())>=run(true,|part|{called.push(part);Ok(())});assert!(result.is_ok());assert_eq!(called,parts(true));}
}
