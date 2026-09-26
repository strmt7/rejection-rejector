use anyhow::{ensure,Result};
use crossbeam_channel::{bounded,Sender};
use serde_json::json;
use std::{sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};
use subtle::ConstantTimeEq;
use tiny_http::{Header,Method,Response,Server};
use crate::worker::Command;

fn authorized(value:Option<&str>,token:&str)->bool {
    let expected=format!("Bearer {token}");
    value.unwrap_or("").as_bytes().ct_eq(expected.as_bytes()).unwrap_u8()==1
}
/// Explicitly read-only. No CORS, literal loopback Host, bearer token, no browser Origin.
pub fn start(port:u16,token:String,commands:Sender<Command>,stop:Arc<AtomicBool>)->Result<()> {
    ensure!(token.len()>=40,"API token lacks required entropy");
    let server=Server::http(format!("127.0.0.1:{port}")).map_err(|e|anyhow::anyhow!("Cannot bind loopback API: {e}"))?;
    std::thread::spawn(move||{
        while !stop.load(Ordering::SeqCst) {
            let request=match server.recv_timeout(Duration::from_millis(250)){Ok(Some(r))=>r,Ok(None)=>continue,Err(_)=>break};
            let auth=request.headers().iter().find(|h|h.field.equiv("Authorization")).map(|h|h.value.as_str());
            let host=request.headers().iter().find(|h|h.field.equiv("Host")).map(|h|h.value.as_str());
            let origin=request.headers().iter().any(|h|h.field.equiv("Origin"));
            let (status,body)=if !authorized(auth,&token)||host!=Some(format!("127.0.0.1:{port}").as_str())||origin {
                (401,json!({"error":"Unauthorized"}))
            } else if request.method()!=&Method::Get {
                (405,json!({"error":"Read-only API"}))
            } else if request.url().len()>2000||!request.url().starts_with("/v1/") {
                (404,json!({"error":"Unknown route"}))
            } else {
                let(tx,rx)=bounded(1);
                if commands.try_send(Command::Api{path:request.url().into(),reply:tx}).is_err(){(503,json!({"error":"Worker busy"}))}
                else {match rx.recv_timeout(Duration::from_secs(3)){Ok(data)=>(if data.get("error").is_some(){400}else{200},data),Err(_)=>(503,json!({"error":"Worker busy; retry later"}))}}
            };
            let response=Response::from_string(body.to_string()).with_status_code(status)
                .with_header(Header::from_bytes("Content-Type","application/json; charset=utf-8").expect("constant header"))
                .with_header(Header::from_bytes("Cache-Control","no-store").expect("constant header"))
                .with_header(Header::from_bytes("X-Content-Type-Options","nosniff").expect("constant header"));
            let _=request.respond(response);
        }
    });Ok(())
}
#[cfg(test)]
mod tests{use super::*;#[test]fn exact_bearer_required(){assert!(authorized(Some("Bearer correct"),"correct"));for v in [None,Some("correct"),Some("Bearer wrong"),Some("Bearer correct ")]{assert!(!authorized(v,"correct"));}}}
