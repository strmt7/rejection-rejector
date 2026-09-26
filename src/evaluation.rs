use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use crate::{config::Settings,ollama::{Ollama,sample_email},types::Category,vault::write_new_private};
#[derive(Deserialize)]
struct Case{id:String,subject:String,text:String,expected:Category}
/// A tiny synthetic regression corpus, not representative accuracy or a model leaderboard.
pub fn run(settings:&Settings,out:&Path)->Result<()> {
    let cases:Vec<Case>=serde_json::from_str(include_str!("../tests/fixtures/classification.json"))?;
    let llm=Ollama::new(settings)?;let model=llm.inspect()?;let mut rows=Vec::new();let mut correct=0usize;let mut false_rejection=0usize;
    for c in &cases {
        let start=std::time::Instant::now();
        match llm.classify(&sample_email(&c.subject,&c.text)) {
            Ok((verdict,complete))=>{let matched=verdict.category==c.expected;correct+=usize::from(matched);false_rejection+=usize::from(verdict.category==Category::Rejection&&c.expected!=Category::Rejection);rows.push(serde_json::json!({"id":c.id,"expected":c.expected,"actual":verdict.category,"match":matched,"input_complete":complete,"seconds":start.elapsed().as_secs_f64(),"evidence":verdict.evidence}));},
            Err(e)=>rows.push(serde_json::json!({"id":c.id,"expected":c.expected,"error":e.to_string(),"match":false})),
        }
    }
    let report=serde_json::json!({"timestamp":chrono::Utc::now(),"model":settings.model,"digest":model.digest,"context":settings.num_ctx,"fixture_count":cases.len(),"correct":correct,"false_rejection":false_rejection,"results":rows,"limitations":"Small synthetic regression set only. Not representative mailbox accuracy, cross-model ranking, GPU peak certification or proof that automatic sending is safe."});
    if let Some(p)=out.parent(){if !p.as_os_str().is_empty(){std::fs::create_dir_all(p)?;}}
    write_new_private(out,&serde_json::to_vec_pretty(&report)?)?;Ok(())
}
#[cfg(test)]
mod tests{use super::*;#[test]fn fixture_ids_are_unique(){let rows:Vec<Case>=serde_json::from_str(include_str!("../tests/fixtures/classification.json")).unwrap();let unique:std::collections::HashSet<_>=rows.iter().map(|c|&c.id).collect();assert_eq!(rows.len(),unique.len());assert!(rows.len()>=10);}}
