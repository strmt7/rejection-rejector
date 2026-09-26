"""One-time, exact-match source finalization. Removed from Git after application."""
from pathlib import Path

def replace(path, before, after):
    p = Path(path)
    text = p.read_text()
    if text.count(before) != 1:
        raise RuntimeError(f'Expected exactly one source match in {path}: {before[:70]}')
    p.write_text(text.replace(before, after))

gui = 'src/gui.rs'
replace(gui, 'time::Duration', 'time::{Duration,Instant}')
replace(gui, 'screenshot_requested:bool,frames:u32,local_error:String,', 'screenshot_requested:bool,frames:u32,local_error:String,started:Instant,')
replace(gui, 'frames:0,local_error:String::new()}', 'frames:0,local_error:String::new(),started:Instant::now()}')
replace(gui, '''            if self.editor_key.as_ref()!=Some(&key)&&!self.dirty {
                self.editor=job.draft.as_ref().map(|d|d.body.clone()).unwrap_or_default();self.editor_key=Some(key);
            }''', '''            let stored=job.draft.as_ref().map(|d|d.body.as_str()).unwrap_or("");
            // A failed save must leave the editor dirty and sending disabled.
            if self.editor_key.as_ref().is_some_and(|k|k.0==job.id)&&self.editor==stored {
                self.dirty=false;self.editor_key=Some(key.clone());
            }
            if self.editor_key.as_ref()!=Some(&key)&&!self.dirty {
                self.editor=stored.into();self.editor_key=Some(key);
            }''')
replace(gui, 'if ui.add_enabled(available&&self.dirty,egui::Button::new("Save changes")).clicked(){self.worker.command(Command::Edit{id:job.id.clone(),revision:job.revision,body:self.editor.clone()});self.dirty=false;}', '''if ui.add_enabled(available&&self.dirty,egui::Button::new("Save changes")).clicked(){
                        match crate::mail::validate_draft(&self.editor){
                            Ok(())=>{self.local_error.clear();self.worker.command(Command::Edit{id:job.id.clone(),revision:job.revision,body:self.editor.clone()});},
                            Err(error)=>self.local_error=error.to_string(),
                        }
                    }''')
replace(gui, 'let can_send=available&&!self.dirty&&job.draft.is_some()', 'let can_send=available&&!self.dirty&&visible_draft_matches(job,&self.editor)')
replace(gui, '        if self.screenshot.is_some()&&s.initialized&&s.selected.is_none(){', '''        if self.screenshot.is_some(){
            // Screenshot mode is restricted to synthetic demo data.
            ctx.request_repaint();
            if self.frames%120==0 {eprintln!("GUI_QA initialized={} fatal={} items={} selected={} requested={} elapsed={:.1}",s.initialized,s.fatal,s.items.len(),s.selected.is_some(),self.screenshot_requested,self.started.elapsed().as_secs_f32());}
        }
        if self.screenshot.is_some()&&s.initialized&&s.selected.is_none(){''')
replace(gui, '            if self.frames>12&&s.selected.is_some()&&!self.screenshot_requested{ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));self.screenshot_requested=true;}', '''            if self.started.elapsed()>Duration::from_secs(2)&&s.selected.is_some()&&!self.screenshot_requested{
                eprintln!("GUI_QA requesting native screenshot");
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));self.screenshot_requested=true;
            }
            if s.fatal||self.started.elapsed()>Duration::from_secs(25){
                eprintln!("GUI_QA failed: initialized={} selected={} error={}",s.initialized,s.selected.is_some(),s.error);
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }''')
replace(gui, 'Ok(())=>ctx.send_viewport_cmd(egui::ViewportCommand::Close),Err(e)=>', 'Ok(())=>{eprintln!("GUI_QA native screenshot saved: {}x{}",img.size[0],img.size[1]);ctx.send_viewport_cmd(egui::ViewportCommand::Close);},Err(e)=>')
with Path(gui).open('a') as f:
    f.write('''
/// Only the exact persisted draft is a valid GUI send candidate.
fn visible_draft_matches(job:&Job,text:&str)->bool {
    job.draft.as_ref().is_some_and(|d|d.body==text)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsaved_editor_never_matches_send_candidate(){
        let email=crate::ollama::sample_email("Synthetic","Synthetic rejection");
        let mut job=Job::new(email.stub,chrono::Utc::now());
        job.draft=Some(crate::types::Draft{body:"Persisted and reviewed reply".into(),origin:"human".into()});
        assert!(visible_draft_matches(&job,"Persisted and reviewed reply"));
        assert!(!visible_draft_matches(&job,"Changed but not saved reply"));
        job.draft=None;assert!(!visible_draft_matches(&job,""));
    }
}
''')
replace('src/bin/desktop.rs', 'let options=eframe::NativeOptions{viewport:', 'let options=eframe::NativeOptions{renderer:eframe::Renderer::Glow,viewport:')
replace('src/bin/desktop.rs', '.with_inner_size([1440.0,940.0])', '.with_visible(true).with_inner_size([1440.0,940.0])')
with Path('src/worker.rs').open('a') as f:
    f.write('''
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn demo_worker_initializes_and_publishes_selection(){
        let dir=tempfile::tempdir().unwrap();
        let worker=Worker::spawn(dir.path().into(),true);
        let start=Instant::now();
        let first=loop{
            let s=worker.view();assert!(!s.fatal,"{}",s.error);
            if s.initialized{assert_eq!(s.items.len(),3);break s.items[0].id.clone();}
            assert!(start.elapsed()<Duration::from_secs(10),"Worker did not initialize");
            std::thread::sleep(Duration::from_millis(10));
        };
        worker.command(Command::Select(first.clone()));
        loop{
            let s=worker.view();assert!(!s.fatal,"{}",s.error);
            if let Some(job)=s.selected{assert_eq!(job.id,first);assert!(job.draft.is_some());break;}
            assert!(start.elapsed()<Duration::from_secs(10),"Worker did not publish selection");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
''')
