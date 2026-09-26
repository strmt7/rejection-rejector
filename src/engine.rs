use crate::{
    config::{Mode, Settings, PROMPT_VERSION},
    evaluation,
    gmail::{Gmail, SendFailureKind},
    mail,
    oauth::{self, Credentials},
    ollama::{self, ModelStatus, Ollama},
    store::Store,
    sync,
    types::*,
    vault::{InstanceLock, Vault},
};
use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub struct Engine {
    pub db: Store,
    pub settings: Settings,
    pub account: String,
    pub model: ModelStatus,
    pub demo: bool,
    pub paused: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
    gmail: Option<Gmail>,
    _lock: InstanceLock,
    _temporary: Option<tempfile::TempDir>,
    pub directory: PathBuf,
}
impl Engine {
    pub fn open(
        directory: PathBuf,
        demo: bool,
        paused: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self> {
        let temporary = if demo {
            Some(tempfile::tempdir()?)
        } else {
            None
        };
        let directory = temporary
            .as_ref()
            .map(|p| p.path().to_path_buf())
            .unwrap_or(directory);
        let lock = InstanceLock::acquire(&directory)?;
        let vault = if demo {
            Vault::random()
        } else {
            Vault::open(&directory)?
        };
        let mut db = Store::open(&directory.join("state.sqlite3"), vault)?;
        db.recover_interrupted_sends()?;
        let mut settings: Settings = db.meta("settings")?.unwrap_or_default();
        let repaired = settings.repair_legacy_automatic_state();
        settings.validate()?;
        if repaired {
            db.set_meta("settings", &settings)?;
            db.log(
                "settings.repaired",
                None,
                "Legacy Automatic mode without a qualified model pin was disabled fail-closed",
            )?;
        }
        let creds: Option<Credentials> = db.meta("google_credentials")?;
        let account = db.meta::<String>("account")?.unwrap_or_default();
        if !account.is_empty() {
            let now = Utc::now();
            db.defer_review_outside_window(&account, settings.cutoff(now), now)?;
        }
        let mut e = Self {
            db,
            settings,
            account,
            model: ModelStatus::default(),
            demo,
            paused,
            stop,
            gmail: creds.map(Gmail::new),
            _lock: lock,
            _temporary: temporary,
            directory,
        };
        if demo {
            e.seed_demo()?;
        }
        Ok(e)
    }
    pub fn connected(&self) -> bool {
        self.gmail.is_some()
    }
    pub fn send_scope(&self) -> bool {
        self.gmail.as_ref().is_some_and(Gmail::can_send)
    }
    pub fn connect(&mut self, path: &Path, send: bool) -> Result<()> {
        ensure!(!self.demo, "Demo mode never connects to a real mailbox");
        let credentials = oauth::login(path, send, &self.stop)?;
        let mut gmail = Gmail::new(credentials.clone());
        let profile = gmail.profile()?;
        let account = mail::mailbox(&profile.email_address)?;
        // Fail closed during an account switch. Persist the complete connection
        // state and audit event together before publishing it to the in-memory engine.
        let mut settings = self.settings.clone();
        settings.disarm_delivery();
        self.db.change_meta(
            &[
                ("settings", serde_json::to_value(&settings)?),
                (
                    "google_credentials",
                    serde_json::to_value(&credentials)?,
                ),
                ("account", serde_json::to_value(&account)?),
            ],
            &[],
            "account.connected",
            "Google credentials encrypted locally; sending remains disabled",
        )?;
        self.settings = settings;
        self.account = account;
        self.gmail = Some(gmail);
        Ok(())
    }
    pub fn disconnect(&mut self) -> Result<()> {
        let mut settings = self.settings.clone();
        settings.disarm_delivery();
        self.db.change_meta(
            &[("settings", serde_json::to_value(&settings)?)],
            &["google_credentials", "account"],
            "account.disconnected",
            "Local credentials removed; revoke Google consent separately if desired",
        )?;
        self.settings = settings;
        self.gmail = None;
        self.account.clear();
        Ok(())
    }
    pub fn update_settings(&mut self, mut settings: Settings) -> Result<()> {
        ensure!(
            !self.demo || !settings.sending_enabled,
            "Demo can never enable sending"
        );
        ensure!(
            !settings.api_allow_writes,
            "Version 0.1 exposes a read-only integration API"
        );
        if settings.mode == Mode::Automatic && self.settings.mode != Mode::Automatic {
            settings.automatic_since = Some(Utc::now());
        }
        if settings.mode == Mode::HumanReview {
            settings.automatic_confirmed = false;
        }
        if settings.model != self.settings.model
            || settings.num_ctx != self.settings.num_ctx
            || settings.ollama_url != self.settings.ollama_url
        {
            settings.model_digest = None;
            settings.disarm_delivery();
            self.model = ModelStatus::default();
        } else {
            settings.model_digest = self.settings.model_digest.clone();
        }
        settings.validate()?;
        ensure!(
            !settings.sending_enabled || self.send_scope(),
            "Reconnect Gmail with send permission before enabling delivery"
        );
        let tightened_window = settings.lookback_days < self.settings.lookback_days;
        self.db.set_meta("settings", &settings)?;
        self.settings = settings;
        if tightened_window && !self.account.is_empty() {
            let now = Utc::now();
            self.db
                .defer_review_outside_window(&self.account, self.settings.cutoff(now), now)?;
        }
        self.db.log(
            "settings.changed",
            None,
            "Settings updated; mode, age window and send gates revalidated",
        )?;
        Ok(())
    }
    pub fn qualify(&mut self) -> Result<()> {
        let mut unpinned = self.settings.clone();
        unpinned.model_digest = None;
        let status = Ollama::new(&unpinned)?.qualify()?;
        self.settings.model_digest = Some(status.digest.clone());
        self.db.set_meta("settings", &self.settings)?;
        self.model = status;
        self.db.log(
            "model.qualified",
            None,
            "Smoke test and Ollama residency check passed; model digest pinned",
        )?;
        Ok(())
    }
    pub fn inspect_model_status(&mut self) -> Result<()> {
        let mut unpinned = self.settings.clone();
        unpinned.model_digest = None;
        let local = Ollama::new(&unpinned)?;
        let mut status = local.inspect()?;
        if let Some(pin) = &self.settings.model_digest {
            let expected = pin.trim_start_matches("sha256:");
            let actual = status.digest.trim_start_matches("sha256:");
            if expected != actual {
                status.gpu_resident = false;
                status.message =
                    "Installed model digest differs from the qualified pin; qualify again".into();
            } else {
                match local.residency(&status.digest) {
                    Ok(resident) => status = resident,
                    Err(error) => {
                        status.gpu_resident = false;
                        status.message = format!(
                            "Pinned model is installed but not currently confirmed GPU-resident: {error}"
                        );
                    }
                }
            }
        }
        self.model = status;
        Ok(())
    }

    pub fn evaluate_model(&mut self) -> Result<PathBuf> {
        ensure!(
            !self.demo,
            "Synthetic demo mode does not run the configured model"
        );
        let stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let path = self
            .directory
            .join(format!("model-evaluation-{stamp}.json"));
        evaluation::run(&self.settings, &path)?;
        self.db.log(
            "model.evaluated",
            None,
            &format!("Synthetic model evaluation saved as {}", path.display()),
        )?;
        Ok(path)
    }

    pub fn synchronize(&mut self) -> Result<usize> {
        ensure!(
            !self.demo,
            "Demo messages are synthetic and have no provider"
        );
        let gmail = self
            .gmail
            .as_mut()
            .context("Connect a Gmail account first")?;
        sync::synchronize(
            gmail,
            &mut self.db,
            &self.settings,
            &self.account,
            Utc::now(),
            &self.stop,
        )
    }
    pub fn last_poll(&self) -> Result<Option<DateTime<Utc>>> {
        Ok(self
            .db
            .meta::<SyncState>(&format!("sync/{}", self.account))?
            .and_then(|s| s.last_poll))
    }
    pub fn process_one(&mut self) -> Result<bool> {
        if self.demo || self.gmail.is_none() || self.settings.model_digest.is_none() {
            return Ok(false);
        }
        let Some(mut job) = self.db.next_queued(&self.account, Utc::now())? else {
            return Ok(false);
        };
        let result = self.analyze_job(&mut job);
        if let Err(error) = result {
            job.attempts = job.attempts.saturating_add(1);
            job.flags = vec![format!("Analysis unavailable: {error}")];
            if job.attempts >= 3 {
                job.state = JobState::Attention;
            } else {
                job.retry_at = Utc::now().timestamp() + 60 * (1i64 << job.attempts.min(6));
            }
            self.db.save(
                &mut job,
                "analysis.failed",
                "Failure recorded; bounded retries, no send authorized",
            )?;
            return Err(error);
        }
        Ok(true)
    }
    fn analyze_job(&mut self, job: &mut Job) -> Result<()> {
        if job.email.is_none() {
            job.email = self
                .gmail
                .as_mut()
                .context("Connect Gmail")?
                .email(&job.stub)?;
        }
        let Some(email) = job.email.as_ref() else {
            job.state = JobState::Other;
            self.db.save(
                job,
                "email.unavailable",
                "Provider message no longer exists",
            )?;
            return Ok(());
        };
        if email.received_at < self.settings.cutoff(Utc::now()) || email.received_at > Utc::now() {
            job.state = JobState::Deferred;
            job.email = None;
            self.db.save(
                job,
                "email.outside_window",
                "Identity retained; body not kept outside requested age range",
            )?;
            return Ok(());
        }
        if email
            .labels
            .iter()
            .any(|s| matches!(s.as_str(), "SENT" | "DRAFT" | "SPAM" | "TRASH"))
        {
            job.state = JobState::Other;
            job.email = None;
            self.db
                .save(job, "email.excluded", "Provider folder excluded")?;
            return Ok(());
        }
        let (analysis, draft, mut flags) = Ollama::new(&self.settings)?.analyze(email)?;
        flags.extend(mail::hard_blocks(email, &self.account));
        let rejected = analysis.verdict.category == Category::Rejection;
        let uncertain = analysis.verdict.category == Category::Uncertain;
        job.state = if rejected
            && flags.is_empty()
            && analysis.verdict.confidence >= 95
            && analysis
                .verification
                .as_ref()
                .is_some_and(Verification::passed)
        {
            JobState::Ready
        } else if rejected || uncertain {
            JobState::Attention
        } else {
            JobState::Other
        };
        job.draft = draft;
        job.drafted_at = job.draft.as_ref().map(|_| Utc::now());
        job.analysis = Some(analysis);
        job.flags = flags;
        job.retry_at = 0;
        if job.state == JobState::Other {
            job.email = None;
            job.analysis = None;
        }
        self.db.save(
            job,
            "email.analyzed",
            "Local structured classification and reply verification completed",
        )?;
        Ok(())
    }
    pub fn edit(&mut self, id: &str, revision: u64, body: String) -> Result<()> {
        ensure!(
            self.settings.mode == Mode::HumanReview,
            "Editing is available only in Human review mode"
        );
        mail::validate_draft(&body)?;
        let mut job = self.owned(id)?;
        ensure!(
            job.state.reviewable() && job.revision == revision,
            "Message changed; reload before editing"
        );
        job.draft = Some(Draft {
            body,
            origin: "human".into(),
        });
        job.drafted_at = Some(Utc::now());
        job.state = JobState::Attention;
        if let Some(a) = job.analysis.as_mut() {
            a.verified_draft_hash = None;
            a.verification = None;
        }
        job.flags = vec!["User-edited reply; previous automatic verification invalidated".into()];
        self.db.save(
            &mut job,
            "draft.edited",
            "Human edit; explicit review required before send",
        )?;
        Ok(())
    }
    pub fn regenerate(&mut self, id: &str, revision: u64) -> Result<()> {
        ensure!(
            self.settings.mode == Mode::HumanReview,
            "Regeneration is available only in Human review mode"
        );
        let mut job = self.owned(id)?;
        ensure!(
            job.state.reviewable() && job.revision == revision,
            "Message changed; reload before regenerating"
        );
        ensure!(!self.demo, "Demo does not run a local model");
        job.attempts = 0;
        job.state = JobState::Queued;
        job.draft = None;
        job.analysis = None;
        job.flags.clear();
        job.retry_at = 0;
        self.db.save(
            &mut job,
            "analysis.requested",
            "User requested a fresh local analysis",
        )?;
        Ok(())
    }
    pub fn dismiss(&mut self, id: &str, revision: u64) -> Result<()> {
        let mut job = self.owned(id)?;
        ensure!(
            job.state.reviewable() && job.revision == revision,
            "Message changed; reload before dismissing"
        );
        job.state = JobState::Dismissed;
        self.db.save(
            &mut job,
            "email.dismissed",
            "Dismissed by user; no mail sent",
        )?;
        Ok(())
    }
    pub fn owned(&self, id: &str) -> Result<Job> {
        let j = self.db.get(id)?;
        ensure!(
            j.stub.account == self.account,
            "Message belongs to another account"
        );
        Ok(j)
    }
    pub fn send(
        &mut self,
        id: &str,
        revision: u64,
        expected_hash: &str,
        automatic: bool,
    ) -> Result<()> {
        ensure!(!self.demo, "Demo messages cannot be sent");
        ensure!(
            !self.paused.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst),
            "Paused or stopping; sending is blocked"
        );
        ensure!(self.settings.sending_enabled, "Sending is disabled");
        ensure!(
            automatic || self.settings.mode == Mode::HumanReview,
            "Manual sending is only available in Human review mode"
        );
        let job = self.owned(id)?;
        ensure!(
            job.revision == revision && job.state.reviewable(),
            "Approval is stale or message is not reviewable"
        );
        mail::validate_job_identity(&job)?;
        let body = &job.draft.as_ref().context("Draft is missing")?.body;
        ensure!(
            hash(body) == expected_hash,
            "Reply changed after confirmation"
        );
        mail::validate_draft(body)?;
        let original = job.email.as_ref().context("Original message missing")?;
        ensure!(
            mail::hard_blocks(original, &self.account).is_empty(),
            "Message is blocked by mailbox safety checks"
        );
        ensure!(
            original.received_at >= self.settings.cutoff(Utc::now()),
            "Original message is outside the selected age window"
        );
        if automatic {
            ensure!(
                auto_blocks(&job, &self.settings, &self.account, Utc::now()).is_empty(),
                "Automatic send conditions were not satisfied"
            );
            let status = Ollama::new(&self.settings)?.inspect()?;
            ensure!(
                status.digest
                    == job
                        .analysis
                        .as_ref()
                        .context("Missing analysis")?
                        .model_digest,
                "Model changed since analysis"
            );
        }
        let gmail = self.gmail.as_mut().context("Gmail is not connected")?;
        ensure!(gmail.can_send(), "Google send permission is missing");
        ensure!(
            mail::mailbox(&gmail.profile()?.email_address)? == self.account,
            "Connected account changed"
        );
        let fresh = gmail
            .email(&job.stub)?
            .context("Original message no longer exists")?;
        ensure!(
            fresh.fingerprint() == original.fingerprint()
                && mail::hard_blocks(&fresh, &self.account).is_empty(),
            "Original message changed; review it again"
        );
        let thread = gmail.thread(&job.stub.thread_id)?;
        ensure!(
            thread.messages.iter().any(|m| m.id == job.stub.provider_id),
            "Original message is no longer in the conversation"
        );
        for message in thread.messages {
            if message.id != job.stub.provider_id {
                let at = message
                    .internal_date
                    .parse::<i64>()
                    .context("Invalid thread date")?;
                ensure!(
                    at < original.received_at.timestamp_millis(),
                    "Newer conversation activity exists; no reply sent"
                );
            }
        }
        let raw = mail::raw_reply(&job, &self.settings, &self.account, Utc::now())?;
        ensure!(
            !self.paused.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst),
            "Paused before dispatch; nothing sent"
        );
        self.db
            .reserve_send(&job, self.settings.daily_send_limit, Utc::now())?;
        // The check is repeated after reservation; cancellation consumes the reservation conservatively.
        if self.paused.load(Ordering::SeqCst) || self.stop.load(Ordering::SeqCst) {
            self.db.release_unsent_reservation(
                id,
                "Dispatch was cancelled before the Gmail network request; no email was sent",
            )?;
            anyhow::bail!("Dispatch cancelled before Gmail accepted any request");
        }
        match self
            .gmail
            .as_mut()
            .context("Gmail disconnected")?
            .send(&raw, &job.stub.thread_id)
        {
            Ok(provider_id) => {
                self.db.finish_send(id, Some(provider_id))?;
                Ok(())
            }
            Err(error) if error.kind == SendFailureKind::NotAccepted => {
                self.db.release_unsent_reservation(
                    id,
                    "Gmail definitively rejected the send request; no email was accepted",
                )?;
                anyhow::bail!("{}", error.message)
            }
            Err(error) => {
                self.db.finish_send(id, None)?;
                anyhow::bail!(
                    "{} Do not resend. Use Reconcile to check Gmail Sent.",
                    error.message
                )
            }
        }
    }
    pub fn automatic_tick(&mut self) -> Result<bool> {
        if self.settings.mode != Mode::Automatic
            || !self.settings.sending_enabled
            || self.paused.load(Ordering::SeqCst)
        {
            return Ok(false);
        }
        if self.db.counts(&self.account)?.attempts_24h >= u64::from(self.settings.daily_send_limit)
        {
            return Ok(false);
        }
        for id in self.db.ready_ids(&self.account)? {
            let job = self.owned(&id)?;
            if self.db.thread_blocked(&job.stub.thread_key())?
                || !auto_blocks(&job, &self.settings, &self.account, Utc::now()).is_empty()
            {
                continue;
            }
            let fingerprint = hash(&job.draft.as_ref().context("Missing draft")?.body);
            if let Err(error) = self.send(&id, job.revision, &fingerprint, true) {
                let mut current = self.owned(&id)?;
                if current.state.reviewable() {
                    current.state = JobState::Attention;
                    current
                        .flags
                        .push(format!("Automatic dispatch stopped: {error}"));
                    self.db.save(
                        &mut current,
                        "automatic.held",
                        "Preflight failed; requires human review",
                    )?;
                }
                return Err(error);
            }
            return Ok(true);
        }
        Ok(false)
    }
    pub fn reconcile(&mut self, id: &str) -> Result<()> {
        let j = self.owned(id)?;
        ensure!(
            j.state == JobState::Uncertain,
            "Only uncertain deliveries can be reconciled"
        );
        let found = self
            .gmail
            .as_mut()
            .context("Connect Gmail")?
            .find_sent(&mail::outgoing_id(&j))?;
        if let Some(provider) = found {
            self.db.finish_send(id, Some(provider))?;
        } else {
            self.db.log(
                "delivery.unresolved",
                Some(id),
                "No Sent match found. Reservation retained; absence does not prove non-delivery",
            )?;
        }
        Ok(())
    }
    fn seed_demo(&mut self) -> Result<()> {
        self.account = "demo@example.invalid".into();
        self.settings.signature = "Alex Morgan".into();
        for (company,subject,text) in [
            ("Northstar Materials","Your application — Thin Film Engineer","Thank you for applying for the Thin Film Engineer position. After reviewing your experience, we have decided not to move forward with your application."),
            ("Helix Instruments","Update on your application","We appreciate your interest in our R&D team. Your application has not been selected for the next stage."),
            ("Aperture Systems","Research Engineer application","Thank you for your time. We have decided to pursue other candidates for this position.")
        ] {
            let email=ollama::sample_email(subject,text);let id=email.stub.id();self.db.insert_stub(email.stub.clone(),Utc::now())?;let mut job=self.db.get(&id)?;
            job.email=Some(email);job.state=JobState::Ready;job.flags=vec!["Synthetic demonstration. No actual account or live inference.".into()];
            job.draft=Some(Draft{body:format!("Dear {company} Recruitment Team,\n\nI challenge this decision and request a substantive explanation of the assessment. Please identify the specific advertised requirements I did not meet and explain how my relevant experience was evaluated. A restatement of the outcome would not address these questions.\n\nRegards,\nAlex Morgan"),origin:"demo".into()});job.drafted_at=Some(Utc::now());
            self.db.save(&mut job,"demo.loaded","Synthetic fixture, not model-generated or real email")?;
        }
        Ok(())
    }
}

pub fn auto_blocks(job: &Job, s: &Settings, account: &str, now: DateTime<Utc>) -> Vec<String> {
    let mut reasons = Vec::new();
    if mail::validate_job_identity(job).is_err() {
        reasons.push("Queue/message identity mismatch".into());
    }
    if s.mode != Mode::Automatic || !s.sending_enabled || !s.automatic_confirmed {
        reasons.push("Automatic mode not explicitly armed".into());
    }
    let Some(email) = job.email.as_ref() else {
        return vec!["Original email missing".into()];
    };
    reasons.extend(mail::hard_blocks(email, account));
    let Some(a) = job.analysis.as_ref() else {
        return vec!["Local analysis missing".into()];
    };
    let Some(draft) = job.draft.as_ref() else {
        return vec!["Draft missing".into()];
    };
    if job.state != JobState::Ready
        || a.verdict.category != Category::Rejection
        || a.verdict.confidence < 95
    {
        reasons.push("Not a high-score reviewed rejection".into());
    }
    if !a.input_complete
        || !a.gpu_resident
        || !a.verification.as_ref().is_some_and(Verification::passed)
    {
        reasons.push("Model verification or residency failed".into());
    }
    if draft.origin != "ollama-v1"
        || a.verified_draft_hash.as_deref() != Some(hash(&draft.body).as_str())
    {
        reasons.push("Draft changed since verification".into());
    }
    if s.model_digest.as_ref() != Some(&a.model_digest)
        || s.model != a.model
        || a.prompt_version != PROMPT_VERSION
        || a.context_hash != ollama::context_hash(s)
        || a.email_fingerprint != email.fingerprint()
    {
        reasons.push("Analysis identity is stale".into());
    }
    if job
        .drafted_at
        .is_none_or(|t| now.signed_duration_since(t).num_minutes() < i64::from(s.cooldown_minutes))
    {
        reasons.push("Cooldown active".into());
    }
    if email.received_at < s.cutoff(now) || email.received_at > now {
        reasons.push("Outside selected age window".into());
    }
    if !s.include_backlog && s.automatic_since.is_none_or(|t| email.received_at < t) {
        reasons.push("Predates automatic-mode enrollment".into());
    }
    if mail::auto_language_conflict(&email.subject, &email.text) {
        reasons.push("Conflicting or suspicious email language".into());
    }
    if mail::automatic_draft_conflict(&draft.body, &s.signature) {
        reasons.push("Draft requires Human review because of escalation or link content".into());
    }
    if email
        .header("auto-submitted")
        .is_some_and(|value| !value.eq_ignore_ascii_case("no"))
    {
        reasons.push("Automatically generated incoming mail requires Human review".into());
    }
    for name in [
        "list-id",
        "list-unsubscribe",
        "precedence",
        "x-auto-response-suppress",
    ] {
        if email.headers.contains_key(name) {
            reasons.push(format!("Automatic replies suppressed by {name}"));
        }
    }
    if let Some(reply) = &email.reply_to {
        if mail::mailbox(reply).ok() != mail::mailbox(&email.from).ok() {
            reasons.push("Reply-To differs from sender; human review required".into());
        }
    }
    reasons
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn demo_is_disarmed_and_editable() {
        let d = tempfile::tempdir().unwrap();
        let mut e = Engine::open(
            d.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert!(!e.settings.sending_enabled);
        let j = e.db.list(&e.account, true, 0, 25).unwrap().remove(0);
        e.edit(
            &j.id,
            j.revision,
            "Please explain the specific assessment criteria used.".into(),
        )
        .unwrap();
        let updated = e.owned(&j.id).unwrap();
        assert_eq!(updated.draft.unwrap().origin, "human");
        assert!(e.send(&j.id, j.revision, "bad", false).is_err());
    }
    #[test]
    fn default_auto_policy_blocks() {
        let s = Settings::default();
        let email = ollama::sample_email("Test", "not selected");
        let mut j = Job::new(email.stub.clone(), Utc::now());
        j.email = Some(email);
        assert!(!auto_blocks(&j, &s, "demo@example.invalid", Utc::now()).is_empty());
    }
}
