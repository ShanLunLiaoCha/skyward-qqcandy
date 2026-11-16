//! Publication is not permission probing: retain the full manifest, query
//! only services this runtime actually needs. Required refusals are fatal.
use anyhow::{ensure,Result};
pub fn probes<'a>(offered:&[String],required:&'a [String])->Result<Vec<&'a str>> {
    let mut result=Vec::new();
    for name in required {ensure!(offered.contains(name),"required service is absent from published declarations: {name}");if !result.contains(&name.as_str()){result.push(name.as_str());}}
    Ok(result)
}
pub fn reload(changed:bool,required_unknown:bool,rewritten:usize)->bool {changed||required_unknown||rewritten>0}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn unrelated_vendor_permission_is_not_a_reentry_precondition(){
  let offered=vec!["KeyMint/default".into(),"VendorUnrelated/default".into()];
  let required=vec!["KeyMint/default".into()];assert_eq!(probes(&offered,&required).unwrap(),["KeyMint/default"]);
  assert_eq!(offered.len(),2);assert!(!reload(false,false,0));
 }
 #[test]fn changed_full_manifest_reloads_even_with_same_required_services(){assert!(reload(true,false,0));assert!(reload(false,true,0));assert!(reload(false,false,1));}
 #[test]fn missing_required_declaration_is_not_silently_ignored(){assert!(probes(&[],&["KeyMint/default".into()]).is_err());}
}
