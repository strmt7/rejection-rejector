#!/usr/bin/env python3
"""Phrase banks for build_corpus_v2.py: multilingual, anti-template email text.

This module is pure data (no side effects, no host-specific paths). It holds the
slot pools (names, companies, positions) and sentence-level fragment banks used
by build_corpus_v2.py to compose stylistically diverse recruiting emails in the
12 supported languages: the ten most-spoken world languages (en, zh, hi, es,
fr, ar, bn, pt, ru, ja) plus German (de) and Greek (el).

Design notes:
  * Emails are COMPOSED from fragments (greeting + optional context + decision
    sentence(s) + optional thanks/reopen lines + closing + optional signature),
    never pasted from a single fixed template. Optional blocks, ordering and
    slot values make near-identical bodies statistically rare.
  * Every fragment may contain slots: {name} {first} {company} {position}
    {skill} {id} {date} {time} {ats} {name2}.
  * Banks per language:
      greet / subject_rej / decision[style] / context / skill_line / thanks /
      reopen / closing / titles                     -> rejections
      neg[type] = {subject, intro, core, extra}     -> hard negatives
      amb[type] = {subject, intro, core, extra}     -> ambiguous (fail closed)
      adv = adversarial near-miss recipes           -> hard negatives
    Non-English languages carry a slightly smaller set of negative types
    (application_ack, interview_invite, offer_letter, job_alert, recruiter_spam,
    newsletter, account_security, adversarial); ATS/scheduling flavours and the
    richest adversarial set are English-first, matching real-world traffic.

Inputs:  imported as a module; see BANKS.
Output:  BANKS dict keyed by language code.
"""

from __future__ import annotations

BANKS: dict = {}

BANKS["en"] = {
    "names": [
        "Sarah Chen",
        "Marcus Silva",
        "Priya Patel",
        "Hannah Okafor",
        "Lucas Meyer",
        "Amara Diallo",
        "Jonas Weber",
        "Emily Novak",
        "David Kim",
        "Rosa Alvarez",
        "Tom Fletcher",
        "Aisha Rahman",
        "Michael O'Brien",
        "Grace Mensah",
        "Laura Lindqvist",
        "Ahmed Hassan",
        "Peter Kovacs",
        "Nina Petrova",
    ],
    "companies": [
        "Innotech",
        "Brightpath Analytics",
        "Northwind Logistics",
        "Helios Health",
        "Cobalt Financial",
        "Redwood Media Group",
        "Atlas Robotics",
        "Bluepeak Consulting",
        "Meridian Retail",
        "Quantum Ledger",
        "Silverline Studios",
        "Orbital Foods",
        "Granite Insurance",
        "Vantage Cloud",
        "Copperfield & Sons",
        "Lumen Education",
        "Peakside Ventures",
        "Fairview Medical Center",
    ],
    "positions": [
        "Senior Backend Engineer",
        "Product Marketing Manager",
        "Data Analyst",
        "Registered Nurse",
        "Warehouse Operations Lead",
        "UX Designer",
        "Account Executive",
        "DevOps Engineer",
        "Financial Controller",
        "Customer Success Manager",
        "Technical Recruiter",
        "Mechanical Engineer",
        "Content Strategist",
        "High School Teacher",
        "Sales Development Representative",
        "Machine Learning Engineer",
        "Office Administrator",
        "Project Manager",
    ],
    "skills": [
        "Python",
        "supply chain",
        "pediatric care",
        "B2B sales",
        "cloud infrastructure",
        "financial modeling",
        "graphic design",
        "curriculum development",
        "SQL",
        "mechanical design",
    ],
    "greet": [
        "Hi {name},",
        "Hi {first},",
        "Dear {name},",
        "Hello {name},",
        "Good afternoon {name},",
        "Good morning {first},",
        "{name},",
    ],
    "subject_rej": [
        "Update on your application",
        "Your application with {company}",
        "Regarding your application for {position}",
        "{position} - your application",
        "Following up on your candidacy",
        "Your recent application",
        "Application update - {company}",
        "Regarding the {position} opening",
        "Your interview process with {company}",
        "{company} hiring process update",
    ],
    "decision": {
        "direct": [
            "We will not be moving forward with your application.",
            "After reviewing your materials, we have decided not to move forward.",
            "You have not been selected for the {position} role.",
            "We are not advancing you to the next stage of the process.",
            "Our team has decided to pursue other candidates.",
            "This is a no from us on the {position} opening.",
            "We will not be making you an offer.",
            "The hiring team has passed on your candidacy for {position}.",
        ],
        "polite": [
            "After careful consideration, we regret to inform you that we will not be proceeding with your candidacy.",
            "We appreciate the time you invested in the process, but we have decided to move "
            "forward with another "
            "candidate.",
            "Thank you for taking the time to interview with us; unfortunately, we will not be "
            "offering you the {position} "
            "position.",
            "It was a pleasure learning about your background. Regretfully, we must decline your "
            "application at this "
            "time.",
            "We met many strong candidates and, after much deliberation, have chosen to proceed with someone else.",
            "We are grateful for your interest in {company} and sorry to say that we will not be "
            "taking your application "
            "further.",
            "While we were impressed with parts of your profile, we have decided not to move forward at this time.",
            "Thank you again for your patience during our process. We will not be extending an "
            "offer for the {position} "
            "role.",
        ],
        "brutal": [
            "No. Your experience does not come close to what this role requires.",
            "You are not qualified for this job. Please do not reapply.",
            "We rejected you because your portfolio was weak and your take-home was late.",
            "Honestly, this was not a close call - we are passing.",
            "Your application was rejected in the first screening and there is no appeal.",
            "We read your application twice and both times the answer was no.",
            "Your profile is far too junior for the {position} seat. We are moving on.",
            "The feedback from the panel was blunt: you are not a fit. We will not proceed.",
        ],
        "vague": [
            "We have decided to go in a different direction.",
            "After an internal review, we are not moving forward with your profile.",
            "We have re-evaluated our needs and will not be proceeding.",
            "Your application has been closed.",
            "We are moving ahead with a different path for this search.",
            "At this point we are not in a position to take your candidacy further.",
            "Our needs have evolved and we will not be continuing with your application.",
            "The role has gone in another direction.",
        ],
        "legal": [
            "Please be advised that {company} has concluded its consideration of your application "
            "and will not extend an offer of "
            "employment.",
            "This letter confirms that your candidacy for the aforementioned position has been "
            "concluded without further "
            "action.",
            "The Company has completed its review of your application and no offer of employment "
            "will be made; this decision is "
            "final.",
            "Nothing in this communication constitutes a contract of employment or any commitment "
            "to future "
            "consideration.",
            "Accordingly, your application for employment is declined and the file will be "
            "retained "
            "in accordance with our records "
            "policy.",
            "Be advised that all consideration of your candidacy has ceased and no further "
            "correspondence will follow on this "
            "matter.",
            "The Company declines to enter into an employment relationship with you in respect of "
            "the position referenced "
            "above.",
        ],
        "agency": [
            "Our client has decided not to proceed with your profile for the contract role.",
            "The hiring manager reviewed your submission and unfortunately they passed.",
            "We submitted you to {company} and they came back with a no - they went with someone "
            "with more {skill} "
            "experience.",
            "Bad news on the {position} role: the client chose another candidate.",
            "The end client has declined your profile and we will keep you in mind for future briefs.",
            "We heard back from the account team and they are not moving forward with you.",
            "The client feedback was that your background did not match the brief closely enough.",
        ],
        "internal": [
            "I wanted to close the loop - the team decided not to move forward with you for the {position} role.",
            "Just heard back from the hiring manager: they are passing on your application. Happy "
            "to keep you in mind for other "
            "teams.",
            "I am sorry to say the panel went with a different candidate. You came close.",
            "Quick update from my side: the answer is no on this one, though I know the team liked you.",
            "Between us, the req got re-scoped and you are no longer in the running for {position}.",
            "I would rather you hear it from me directly: we are not moving forward with your application.",
            "The debrief is done and the decision is not to proceed. I am happy to share brief feedback if useful.",
        ],
        "ats": [
            "Your application for {position} (ID {id}) has not been selected for further consideration.",
            "Status update: Not Selected. Thank you for your interest in {company}.",
            "Dear Applicant, this is an automated notification that your candidacy has been closed.",
            "Your profile has been moved to the 'Rejected' stage in our applicant tracking system.",
            "Following an automated review, your application has been archived and will not progress.",
            "Your job application (ID {id}) has been marked as not selected by the recruiting team.",
            "This is an automated status change for the {position} requisition: Application closed - not selected.",
        ],
    },
    "context": [
        "We received over 600 applications for this role.",
        "This was a competitive search and the decision took some time.",
        "The panel met on Friday to review the remaining candidates.",
        "We had a strong slate of applicants this cycle.",
        "Please know this decision was not made lightly.",
        "We wanted to get back to you as soon as the decision was final.",
    ],
    "skill_line": [
        "Your background in {skill} was not quite what the team needed.",
        "The role leaned heavily toward {skill}, which we did not see enough of.",
        "We were looking for deeper hands-on experience with {skill}.",
        "The gap that decided it was the {skill} requirement.",
    ],
    "thanks": [
        "Thank you for the time you put into the process.",
        "We appreciate your interest in {company}.",
        "Thanks for taking the time to speak with the team.",
        "We are grateful you considered joining {company}.",
        "Thank you for your patience while we worked through the process.",
    ],
    "reopen": [
        "We will keep your resume on file for future openings.",
        "Please feel free to apply again when new roles open.",
        "You are welcome to reapply in six months.",
        "We will keep an eye out for roles that might suit you.",
    ],
    "closing": [
        "Best regards,",
        "Kind regards,",
        "Sincerely,",
        "All the best,",
        "Regards,",
        "Best,",
        "Yours truly,",
        "With thanks,",
    ],
    "titles": [
        "Recruiter",
        "Talent Acquisition Partner",
        "Hiring Manager",
        "HR Coordinator",
        "Head of Talent",
        "Recruiting Coordinator",
        "People Operations",
        "Technical Recruiter",
    ],
    "neg": {
        "application_ack": {
            "subject": [
                "We received your application",
                "Application received - {position}",
                "Thanks for applying to {company}",
            ],
            "intro": ["Hi {first},", "Hello {first},", "Dear Applicant,"],
            "core": [
                "Thanks for applying for the {position} role at {company} - we received your application.",
                "Your application for {position} (ID {id}) has been received and is now in review.",
                "We have your application for the {position} opening and the recruiting team will take a look.",
            ],
            "extra": [
                "You can check your status any time in our candidate portal.",
                "This mailbox is unattended, so please do not reply to this email.",
                "We typically respond within ten business days.",
            ],
        },
        "interview_invite": {
            "subject": [
                "Interview invitation - {position}",
                "Next step: let's talk",
                "Your application to {company}: interview",
            ],
            "intro": ["Hi {first},", "Hello {first},", "Dear {name},"],
            "core": [
                "We would like to invite you to a 45-minute interview for the {position} role.",
                "The team enjoyed your application and would like to move you to the next step.",
                "You have been selected for an interview - please pick a slot that works for you.",
            ],
            "extra": [
                "Use the link below to choose a time with the hiring manager.",
                "The interview will cover your experience with {skill} and a short exercise.",
                "Please bring two references to the call.",
            ],
        },
        "offer_letter": {
            "subject": [
                "Offer of employment - {company}",
                "We would like to offer you the {position} role",
                "Good news: your offer",
            ],
            "intro": ["Hi {first},", "Dear {name},"],
            "core": [
                "We are delighted to offer you the position of {position} at {company}.",
                "It is my pleasure to extend an offer for the {position} role.",
                "After a successful final round, we would like to bring you on board.",
            ],
            "extra": [
                "Compensation details are attached; please sign by {date}.",
                "Your start date is {date} and benefits begin on day one.",
                "Welcome aboard - your recruiter will follow up with onboarding steps.",
            ],
        },
        "job_alert": {
            "subject": [
                "New jobs for you",
                "Recommended openings this week",
                "Job alert: roles matching your profile",
            ],
            "intro": ["Hi {first},", "Hello {first},"],
            "core": [
                "Based on your profile, we picked a few new openings for you.",
                "{company} is hiring for several positions; take a look.",
                "Your weekly job alert: 7 new roles match your saved search.",
            ],
            "extra": [
                "Unsubscribe from these alerts using the link below.",
                "See more openings on our website.",
                "Update your job preferences any time.",
            ],
        },
        "recruiter_spam": {
            "subject": [
                "Quick question about your background",
                "Your profile stood out to me",
                "Opportunities in {skill}",
            ],
            "intro": ["Hi {first},", "Hello {first},", "Hey {first},"],
            "core": [
                "I came across your profile and wanted to reach out about roles in the {skill} space.",
                "We are hiring for several positions and your experience caught my eye.",
                "Are you open to hearing about new opportunities this quarter?",
            ],
            "extra": [
                "Even if the timing is wrong, it would be great to connect.",
                "I have attached a few job descriptions that might interest you.",
                "Reply with your CV and I will keep you in mind.",
            ],
        },
        "newsletter": {
            "subject": [
                "The Hiring Loop Weekly",
                "Your Monday dose of career advice",
                "Issue #128: negotiation tactics",
            ],
            "intro": ["Hi {first},", "Hello there,"],
            "core": [
                "Welcome to your weekly digest from The Hiring Loop.",
                "This week we look at how to negotiate a relocation package.",
                "Our latest issue covers portfolio tips for career switchers.",
            ],
            "extra": [
                "Forward this to someone deep in a job search.",
                "Reply with your story and we will run the best ones.",
                "You are receiving this because you subscribed at hiringloop.example.",
            ],
        },
        "marketing": {
            "subject": [
                "Crush your next job search",
                "50% off career coaching this week only",
                "New course: land the offer",
            ],
            "intro": ["Hi {first},", "Hey {first},"],
            "core": [
                "Our new course 'Crushing Rejections' shows you how to turn 47 rejection letters into 3 offers.",
                "Book a free 20-minute career audit before Friday.",
                "This week only: resume rewrites at half price.",
            ],
            "extra": [
                "Offer ends Sunday at midnight.",
                "Join 12,000 job seekers who already enrolled.",
                "Use code HUSTLE at checkout.",
            ],
        },
        "account_security": {
            "subject": [
                "New sign-in to your account",
                "Security alert: unusual activity",
                "Action needed: verify your email",
            ],
            "intro": ["Hi {first},"],
            "core": [
                "We noticed a new sign-in to your account from a new device.",
                "Someone requested a password reset for your account.",
                "Your session token expires in 24 hours; confirm your email to keep access.",
            ],
            "extra": [
                "If this was not you, secure your account immediately.",
                "No action is needed if you recognize this activity.",
                "Never share your verification codes with anyone.",
            ],
        },
        "scheduling_tool": {
            "subject": [
                "Interview scheduled: {position}",
                "Invitation: Interview - {position} - {date}",
                "Event confirmed",
            ],
            "intro": [""],
            "core": [
                "An interview for the {position} role has been scheduled for {date} at {time}.",
                "{name} has invited you to an event via {ats}.",
                "Your meeting with the {company} recruiting team is confirmed for {date}.",
            ],
            "extra": [
                "Reschedule or cancel using the link in this invitation.",
                "A calendar file is attached to this message.",
                "Add this event to your calendar to get reminders.",
            ],
        },
        "ats_notification": {
            "subject": [
                "New application received",
                "Candidate stage changed",
                "Your daily recruiting digest",
            ],
            "intro": ["Hi {first},"],
            "core": [
                "Candidate {name} was rejected for the {position} role by hiring manager {name2}.",
                "You have 12 new applications waiting in the {ats} pipeline.",
                "3 candidates moved to Onsite and 1 was declined today in {ats}.",
            ],
            "extra": [
                "Open {ats} to review the remaining candidates.",
                "You are receiving this because you are the job admin for this requisition.",
                "Set notification preferences in your {ats} settings.",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["Keeping in touch", "Your profile at {company}", "Stay in touch"],
            "intro": ["Hi {first},", "Hello {first},"],
            "core": [
                "We were impressed with your profile and will keep you in mind for future openings.",
                "Let's stay in touch - the team may have needs again next quarter.",
                "Nothing is decided on our side; we genuinely want to keep the conversation going.",
            ],
            "extra": [
                "Feel free to reach out any time.",
                "I will circle back when something opens up.",
            ],
        },
        "resume_on_file": {
            "subject": ["Your application with {company}", "Our talent pool", "Your profile"],
            "intro": ["Dear {name},", "Hi {first},"],
            "core": [
                "Your resume has been added to our talent pool.",
                "We will keep your resume on file and reach out if a suitable role opens.",
                "Your details are now in our system for future consideration.",
            ],
            "extra": [
                "No further action is needed from you.",
                "You can update your profile in our portal.",
            ],
        },
        "on_hold": {
            "subject": [
                "Update on the {position} role",
                "{company} hiring update",
                "Regarding your application",
            ],
            "intro": ["Hi {first},", "Dear {name},"],
            "core": [
                "We have decided to pause hiring for the {position} role.",
                "The {position} requisition is on hold pending budget approval.",
                "Hiring for this team is frozen until the new fiscal year.",
            ],
            "extra": [
                "We will reach out once the situation changes.",
                "Thank you for your patience in the meantime.",
            ],
        },
        "forwarded_mixed": {
            "subject": [
                "Fwd: candidate decision letter",
                "Draft wording - quick look?",
                "Re: {position} search notes",
            ],
            "intro": ["Hi {first},", "Hey,"],
            "core": [
                "Fwd: candidate decision letter - is this wording fine from a legal standpoint?",
                "Thoughts on this draft before I send it? The candidate is expecting news this week.",
                "Forwarding the hiring manager's notes on the {position} search; nothing to "
                "communicate externally "
                "yet.",
            ],
            "extra": [
                "Nothing about your own application has changed.",
                "Happy to jump on a call about this.",
            ],
        },
        "withdrawn": {
            "subject": [
                "Update on the {position} process",
                "{company} recruiting update",
                "Your application",
            ],
            "intro": ["Hi {first},", "Dear {name},"],
            "core": [
                "We regret that the process for the {position} role has been suspended.",
                "The offer process for this role is on hold pending budget sign-off.",
                "We are re-opening the search and have not made a final decision on any candidate.",
            ],
            "extra": [
                "We will keep your application active in the meantime.",
                "Thank you for your understanding.",
            ],
        },
        "assessment": {
            "subject": [
                "Your assessment results",
                "Assessment complete - next steps",
                "{company} assessment update",
            ],
            "intro": ["Hi {first},", "Dear Applicant,"],
            "core": [
                "Your assessment score was 62%; unfortunately you did not meet the threshold. You may retake it once.",
                "We regret that your test result fell below the cutoff for the {position} process.",
                "Assessment complete: 4 of 8. A recruiter will review the results shortly.",
            ],
            "extra": [
                "Results are available in the candidate portal.",
                "Contact assessments@{company}.example with questions.",
            ],
        },
    },
    "adv": {
        "subject": [
            "How we crushed rejections at JobHuntConf",
            "Your application was rejected!",
            "Your payment was rejected",
            "Re: your interview tomorrow",
            "The art of the rejection letter",
            "Interview Quest - weekly recap",
            "Your saved job was filled",
            "Security code for your account",
        ],
        "intro": ["Hi {first},", "Hello {first},", "Hey {first},"],
        "core": [
            (
                "Your application was rejected! You scored 2 out of 5 in Interview Quest and your "
                "in-game application was rejected. Try "
                "again?",
                "other",
            ),
            (
                "Unfortunately, we cannot extend the signing bonus beyond $5,000 - but we are "
                "thrilled to offer you the {position} "
                "role!",
                "opportunity",
            ),
            (
                "We regret to inform you that this week's issue is short: the editor was busy "
                "collecting rejection stories from our "
                "readers.",
                "other",
            ),
            (
                "Your payment was rejected by your bank. Update your card to keep your {company} "
                "Premium subscription "
                "active.",
                "other",
            ),
            (
                "Our new webinar 'Crushing Rejections' teaches you what to do when a company "
                "regrets to inform you of "
                "anything.",
                "other",
            ),
            (
                "We regret that our scheduling tool failed earlier today; your interview for the "
                "{position} role is confirmed for Tuesday at "
                "14:00.",
                "opportunity",
            ),
            (
                "Unfortunately the {position} role you saved at {company} has been filled - here "
                "are five similar roles you may "
                "like.",
                "other",
            ),
            (
                "You joined this list after downloading our rejection-letter templates; this "
                "series "
                "is called 'The Art of the Rejection "
                "Letter'.",
                "other",
            ),
            (
                "Unfortunatley we cannot ship to your region - your order was rejected by our "
                "payment provider and "
                "refunded.",
                "other",
            ),
            (
                "The candidate was rejected in {ats} last week and the req was re-opened; you are "
                "receiving this as the job "
                "admin.",
                "other",
            ),
            (
                "Good news first: you are through to the final round. Unfortunately the panel has "
                "not finished scoring, so timing "
                "slipped.",
                "opportunity",
            ),
            (
                "Our survey on rejection letters closes Friday - unfortunately responses have been slow this year.",
                "other",
            ),
        ],
        "extra": [
            "Reply STOP to opt out of these tips.",
            "The game resets every Monday - good luck.",
            "Nothing about your real application has changed.",
            "Full terms are on our website.",
        ],
    },
}

BANKS["es"] = {
    "names": [
        "Maria Gonzalez",
        "Carlos Rivera",
        "Lucia Fernandez",
        "Javier Morales",
        "Sofia Ramirez",
        "Diego Herrera",
        "Valentina Torres",
        "Andres Navarro",
    ],
    "companies": [
        "Tecnova",
        "Grupo Andina",
        "Salud Integral",
        "Financiera Horizonte",
        "Logistica del Sur",
        "Medios Aurora",
        "Consultores Alborada",
        "Retail Camino",
    ],
    "positions": [
        "Ingeniero Backend Senior",
        "Analista de Datos",
        "Responsable de Marketing",
        "Enfermero/a Registrado/a",
        "Disenador UX",
        "Ejecutivo de Ventas",
        "Contador Financiero",
        "Gerente de Proyectos",
    ],
    "skills": [
        "Python",
        "logistica",
        "ventas B2B",
        "diseno grafico",
        "analisis financiero",
        "atencion al cliente",
    ],
    "greet": ["Hola {name},", "Estimado/a {name},", "Buenos dias {name},", "Hola {first},"],
    "subject_rej": [
        "Actualizacion sobre su candidatura",
        "Su solicitud en {company}",
        "Sobre su candidatura al puesto de {position}",
        "Resultado del proceso - {company}",
        "Su postulacion",
    ],
    "decision": {
        "direct": [
            "No seguiremos adelante con su candidatura.",
            "Tras revisar su perfil, hemos decidido no avanzar con su solicitud.",
            "No ha sido seleccionado/a para el puesto de {position}.",
            "No le estamos convocando a la siguiente etapa del proceso.",
        ],
        "polite": [
            "Tras una cuidadosa consideracion, lamentamos informarle que no seguiremos con su candidatura.",
            "Agradecemos el tiempo que dedico al proceso, pero hemos decidido continuar con otro/a candidato/a.",
            "Lamentablemente no le ofreceremos el puesto de {position} en esta ocasion.",
            "Fue un placer conocer su trayectoria; lamentablemente debemos declinar su solicitud.",
        ],
        "brutal": [
            "No. Su experiencia no se acerca a lo que este puesto exige.",
            "No esta calificado/a para este trabajo. Por favor no vuelva a postular.",
            "Le rechazamos porque su portafolio fue debil y la prueba llego tarde.",
            "Leimos su candidatura dos veces y las dos la respuesta fue no.",
        ],
        "vague": [
            "Hemos decidido ir en otra direccion.",
            "Tras una revision interna, no avanzamos con su perfil.",
            "Sus necesidades han cambiado y no seguiremos con su solicitud.",
            "Su candidatura ha sido cerrada.",
        ],
        "legal": [
            "Se le informa que {company} ha concluido la consideracion de su solicitud y no "
            "extendera oferta de empleo "
            "alguna.",
            "La presente carta confirma que su candidatura para la posicion mencionada ha sido "
            "concluida sin mas "
            "tramite.",
            "La Sociedad ha completado su revision y no se realizara oferta de empleo; esta decision es definitiva.",
            "Nada en esta comunicacion constituye contrato de empleo ni compromiso alguno de consideracion futura.",
        ],
        "agency": [
            "Nuestro cliente ha decidido no continuar con su perfil para el puesto por contrato.",
            "El responsable reviso su perfil y lamentablemente no avanzan.",
            "Le postulamos en {company} y la respuesta fue negativa: eligieron a alguien con mas "
            "experiencia en "
            "{skill}.",
            "Malas noticias sobre el puesto de {position}: el cliente eligio a otro/a candidato/a.",
        ],
        "internal": [
            "Queria ponerlo/a al dia: el equipo decidio no avanzar con usted para el puesto de {position}.",
            "Acabo de hablar con el responsable de contratacion: no siguen adelante con su candidatura.",
            "Lamento decirle que el panel eligio a otro/a candidato/a.",
            "El proceso se redefinio y ya no sigue en la carrera por {position}.",
        ],
        "ats": [
            "Su solicitud para el puesto de {position} (ID {id}) no ha sido seleccionada para mayor consideracion.",
            "Actualizacion de estado: No seleccionado/a. Gracias por su interes en {company}.",
            "Estimado/a postulante: esta es una notificacion automatica de que su candidatura ha sido cerrada.",
            "Su perfil ha sido movido al estado 'Rechazado' en nuestro sistema de seguimiento de candidatos.",
        ],
    },
    "context": [
        "Recibimos mas de 600 solicitudes para este puesto.",
        "Fue un proceso muy competitivo.",
        "El panel se reunio el viernes para evaluar a los candidatos restantes.",
        "Sepa que esta decision no fue ligera.",
    ],
    "skill_line": [
        "Su experiencia en {skill} no era exactamente lo que el equipo necesitaba.",
        "El puesto exigia mas experiencia practica en {skill}.",
    ],
    "thanks": [
        "Gracias por el tiempo que dedico al proceso.",
        "Agradecemos su interes en {company}.",
        "Gracias por su paciencia durante el proceso.",
    ],
    "reopen": [
        "Guardaremos su curriculum para futuras vacantes.",
        "Puede volver a postular cuando haya nuevos puestos.",
        "Estaremos atentos a vacantes que puedan convenirle.",
    ],
    "closing": ["Saludos cordiales,", "Atentamente,", "Un saludo,", "Cordialmente,"],
    "titles": [
        "Reclutador/a",
        "Talento Humano",
        "Responsable de Contratacion",
        "Coordinador/a de RR. HH.",
    ],
    "neg": {
        "application_ack": {
            "subject": ["Recibimos su solicitud", "Solicitud recibida - {position}"],
            "intro": ["Hola {first},", "Estimado/a postulante,"],
            "core": [
                "Gracias por postular al puesto de {position} en {company}; hemos recibido su solicitud.",
                "Su solicitud para el puesto de {position} (ID {id}) ha sido recibida y esta en revision.",
            ],
            "extra": [
                "Puede consultar su estado en el portal de candidatos.",
                "Este buzon no recibe respuestas; por favor no responda a este correo.",
            ],
        },
        "interview_invite": {
            "subject": ["Invitacion a entrevista - {position}", "Siguiente paso: hablemos"],
            "intro": ["Hola {first},", "Estimado/a {name},"],
            "core": [
                "Nos gustaria invitarle a una entrevista de 45 minutos para el puesto de {position}.",
                "Al equipo le gusto su candidatura y quisiera pasar a la siguiente etapa.",
            ],
            "extra": [
                "Use el enlace inferior para elegir un horario.",
                "La entrevista abordara su experiencia en {skill}.",
            ],
        },
        "offer_letter": {
            "subject": [
                "Oferta de empleo - {company}",
                "Queremos ofrecerle el puesto de {position}",
            ],
            "intro": ["Estimado/a {name},", "Hola {first},"],
            "core": [
                "Nos complace ofrecerle el puesto de {position} en {company}.",
                "Tras una ultima entrevista exitosa, queremos incorporarle al equipo.",
            ],
            "extra": [
                "Los detalles de remuneracion estan adjuntos; firme antes del {date}.",
                "Su fecha de inicio sera el {date}.",
            ],
        },
        "job_alert": {
            "subject": ["Nuevas vacantes para usted", "Ofertas de empleo recomendadas"],
            "intro": ["Hola {first},"],
            "core": [
                "Segun su perfil, le recomendamos algunas vacantes nuevas.",
                "{company} esta contratando para varios puestos; eche un vistazo.",
            ],
            "extra": [
                "Deje de recibir estos correos desde el enlace de baja.",
                "Encuentre mas vacantes en nuestro sitio web.",
            ],
        },
        "recruiter_spam": {
            "subject": [
                "Quisiera hablar con usted sobre oportunidades",
                "Su perfil llamo mi atencion",
            ],
            "intro": ["Hola {first},", "Buenos dias {first},"],
            "core": [
                "Vi su perfil y quisiera hablarle sobre oportunidades en {skill}.",
                "Estamos contratando para varios puestos y su experiencia encaja bien.",
            ],
            "extra": [
                "Aunque el momento no sea el ideal, me gustaria mantener el contacto.",
                "Si le parece, envieme su curriculum.",
            ],
        },
        "newsletter": {
            "subject": ["Semanal de empleo, numero 128", "Su dosis semanal de consejos"],
            "intro": ["Hola {first},"],
            "core": [
                "Bienvenido/a a su resumen semanal de El Circulo del Empleo.",
                "Esta semana hablamos de como negociar un paquete de reubicacion.",
            ],
            "extra": [
                "Reenvie este correo a alguien en busqueda activa.",
                "Recibe este correo porque se suscribio en nuestro sitio.",
            ],
        },
        "account_security": {
            "subject": [
                "Nuevo inicio de sesion en su cuenta",
                "Alerta de seguridad: actividad inusual",
            ],
            "intro": ["Hola {first},"],
            "core": [
                "Detectamos un inicio de sesion en su cuenta desde un dispositivo nuevo.",
                "Alguien solicito restablecer la clave de su cuenta.",
            ],
            "extra": [
                "Si no fue usted, asegure su cuenta de inmediato.",
                "Nunca comparta sus codigos de verificacion.",
            ],
        },
        "adversarial": {
            "subject": [
                "Su solicitud fue rechazada!",
                "Pago rechazado",
                "Re: su entrevista de manana",
            ],
            "intro": ["Hola {first},", "Hey {first},"],
            "core": [
                "Su solicitud fue rechazada! - saco 2 de 5 en Interview Quest y su solicitud "
                "dentro "
                "del juego fue rechazada. Intentelo de "
                "nuevo?",
                "Lamentablemente no podemos ampliar la bonificacion de firma - pero nos complace "
                "ofrecerle el puesto de "
                "{position}!",
                "Su banco rechazo el pago. Actualice su tarjeta para mantener su suscripcion Premium de {company}.",
                "Lastimosamente la vacante de {position} que guardo en {company} ya se cubrio; "
                "aqui "
                "van cinco vacantes "
                "similares.",
            ],
            "extra": [
                "Responda BAJA para dejar de recibir estos consejos.",
                "Nada ha cambiado respecto de su solicitud real.",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["Mantengamonos en contacto", "Su perfil en {company}"],
            "intro": ["Hola {first},", "Estimado/a {name},"],
            "core": [
                "Su perfil nos parecio interesante y lo tendremos en cuenta para futuras vacantes.",
                "Sigamos en contacto; el equipo puede volver a tener necesidades el proximo trimestre.",
            ],
            "extra": [
                "No dude en escribirme cuando quiera.",
                "Volvere a contactarle cuando haya algo concreto.",
            ],
        },
        "resume_on_file": {
            "subject": ["Su solicitud en {company}", "Nuestra bolsa de talento"],
            "intro": ["Estimado/a {name},", "Hola {first},"],
            "core": [
                "Su curriculum ha sido anadido a nuestra bolsa de talento.",
                "Conservaremos su curriculum y le contactaremos si surge un puesto adecuado.",
            ],
            "extra": ["No se requiere ninguna accion de su parte."],
        },
        "on_hold": {
            "subject": [
                "Actualizacion sobre el puesto de {position}",
                "Novedades de contratacion en {company}",
            ],
            "intro": ["Hola {first},", "Estimado/a {name},"],
            "core": [
                "Hemos decidido pausar la contratacion para el puesto de {position}.",
                "La vacante de {position} esta en pausa a la espera de aprobacion presupuestaria.",
            ],
            "extra": ["Le avisaremos cuando la situacion cambie.", "Gracias por su paciencia."],
        },
        "assessment": {
            "subject": ["Resultados de su evaluacion", "Evaluacion completada"],
            "intro": ["Hola {first},", "Estimado/a postulante,"],
            "core": [
                "Su puntuacion fue 62%; lamentablemente no alcanzo el umbral. Puede repetir la prueba una vez.",
                "Lamentamos que su resultado haya quedado por debajo del corte del proceso para {position}.",
            ],
            "extra": ["Los resultados estan disponibles en el portal de candidatos."],
        },
    },
    "adv": {
        "subject": [
            "Como aplastamos los rechazos en JobHuntConf",
            "Su solicitud fue rechazada!",
            "Su pago fue rechazado",
            "El arte de la carta de rechazo",
        ],
        "intro": ["Hola {first},", "Hey {first},"],
        "core": [
            (
                "Su solicitud fue rechazada! Saco 2 de 5 en Interview Quest y su solicitud dentro "
                "del juego fue rechazada. Intente otra "
                "vez?",
                "other",
            ),
            (
                "Lamentablemente no podemos ampliar la bonificacion de firma - pero nos complace "
                "ofrecerle el puesto de "
                "{position}!",
                "opportunity",
            ),
            (
                "Lamentamos informar que este numero es corto: la editora estaba ocupada "
                "recogiendo "
                "historias de rechazos de nuestros "
                "lectores.",
                "other",
            ),
            (
                "Lamentablemente la vacante de {position} que guardo en {company} ya se cubrio; "
                "aqui van cinco vacantes "
                "similares.",
                "other",
            ),
            (
                "Su entrevista para el puesto de {position} esta confirmada para el martes a las "
                "14:00; lamentamos el fallo de la herramienta "
                "anterior.",
                "opportunity",
            ),
        ],
        "extra": [
            "Responda BAJA para darse de baja.",
            "Nada ha cambiado respecto de su solicitud real.",
            "Los terminos completos estan en nuestro sitio web.",
        ],
    },
}

BANKS["zh"] = {
    "names": ["李明", "王芳", "张伟", "刘洋", "陈静", "杨帆", "赵敏", "周杰"],
    "companies": [
        "创新科技",
        "华信数据",
        "蓝湾医疗",
        "远航物流",
        "金桥金融",
        "明德教育",
        "星原传媒",
        "云图智能",
    ],
    "positions": [
        "高级后端工程师",
        "数据分析师",
        "市场经理",
        "注册护士",
        "UX 设计师",
        "客户成功经理",
        "财务主管",
        "项目经理",
    ],
    "skills": ["Python", "供应链管理", "B2B 销售", "数据分析"],
    "greet": ["{name} 您好：", "{name}，您好：", "{first} 您好："],
    "subject_rej": [
        "关于您的求职申请",
        "{company} 招聘进展通知",
        "应聘 {position} 岗位的结果",
        "您的申请状态更新",
    ],
    "decision": {
        "direct": [
            "我们不会继续推进您的申请。",
            "经过评估，我们决定不再推进您的申请。",
            "您未被选中进入 {position} 岗位的下一环节。",
            "我们不会向您发放录用通知。",
        ],
        "polite": [
            "经过慎重考虑，我们很遗憾地通知您，我们不会继续推进您的申请。",
            "感谢您投入的时间，但我们已决定录用其他候选人。",
            "很遗憾，本次我们无法为您提供 {position} 岗位。",
            "很高兴与您交流，但我们需要婉拒您的申请。",
        ],
        "brutal": [
            "不行。您的经历与这个岗位的要求相差甚远。",
            "您不符合这份工作的要求，请勿再次申请。",
            "我们拒绝了您，因为您的作品集很弱，作业也迟交了。",
            "我们把您的申请看了两遍，答案都是不。",
        ],
        "vague": [
            "我们决定朝另一个方向推进。",
            "经过内部讨论，我们不会继续推进您的资料。",
            "您的申请已关闭。",
            "我们的需求发生了变化，无法继续推进您的申请。",
        ],
        "legal": [
            "特此告知，{company} 已完成对您申请的审核，不会向您发出任何录用要约。",
            "本函确认，您对上述职位的候选资格已结束，不再另行处理。",
            "公司已完成审核，不会发出录用要约；此决定为最终决定。",
            "本邮件不构成劳动合同或任何未来考虑的承诺。",
        ],
        "agency": [
            "我们的客户决定不继续考虑您的资料。",
            "招聘经理审阅了您的材料，很遗憾未通过。",
            "我们已将您推荐至 {company}，对方婉拒了，他们选择了在 {skill} 方面经验更丰富的候选人。",
            "{position} 岗位有坏消息：客户选择了其他候选人。",
        ],
        "internal": [
            "跟您同步一下：团队决定不继续推进您应聘 {position} 岗位。",
            "刚得到招聘经理的反馈，他们不会继续推进您的申请。",
            "很遗憾，面试小组选择了其他候选人。",
            "这个岗位重新调整了需求，您不再在 {position} 的候选名单中。",
        ],
        "ats": [
            "您申请的 {position} 岗位（编号 {id}）未进入下一环节。",
            "状态更新：未录用。感谢您对 {company} 的关注。",
            "尊敬的申请人：这是自动通知，您的候选流程已关闭。",
            "您的资料已在我司招聘系统中被标记为未通过。",
        ],
    },
    "context": [
        "本次招聘我们收到了六百多份申请。",
        "这个岗位竞争非常激烈。",
        "面试小组上周五开会讨论了剩余候选人。",
        "这个决定并非轻率做出。",
    ],
    "skill_line": [
        "您在 {skill} 方面的背景与团队的需求不完全匹配。",
        "该岗位对 {skill} 的实际经验要求更高。",
    ],
    "thanks": [
        "感谢您在招聘过程中投入的时间。",
        "感谢您对 {company} 的关注。",
        "感谢您的耐心等待。",
    ],
    "reopen": [
        "我们会保留您的简历，供日后职位参考。",
        "有新职位开放时欢迎您再次申请。",
        "我们会留意适合您的机会。",
    ],
    "closing": ["此致敬礼", "顺祝商祺", "祝好", "此致"],
    "titles": ["招聘专员", "人才获取经理", "招聘经理", "人力资源专员"],
    "neg": {
        "application_ack": {
            "subject": ["我们已收到您的申请", "申请已收到 - {position}"],
            "intro": ["{name} 您好：", "您好："],
            "core": [
                "感谢您申请 {company} 的 {position} 岗位，我们已收到您的申请。",
                "您申请的 {position} 岗位（编号 {id}）已收到，正在审核中。",
            ],
            "extra": ["您可以在候选人门户中随时查看进度。", "本邮箱无人值守，请勿直接回复。"],
        },
        "interview_invite": {
            "subject": ["面试邀请 - {position}", "下一步：与您沟通"],
            "intro": ["{name} 您好："],
            "core": [
                "我们想邀请您参加 {position} 岗位的面试。",
                "团队对您的申请很感兴趣，希望进入下一环节。",
            ],
            "extra": ["请通过下方链接选择合适的时间。", "面试将围绕您在 {skill} 方面的经验展开。"],
        },
        "offer_letter": {
            "subject": ["录用通知 - {company}", "我们希望录用您担任 {position}"],
            "intro": ["{name} 您好："],
            "core": [
                "我们很高兴向您发出 {company} {position} 岗位的录用通知。",
                "经过终面，我们希望邀请您加入团队。",
            ],
            "extra": ["薪酬详情见附件，请于 {date} 前签署。", "入职日期为 {date}。"],
        },
        "job_alert": {
            "subject": ["为您推荐新职位", "热门职位推荐"],
            "intro": ["{first} 您好："],
            "core": [
                "根据您的资料，我们为您推荐了几个新职位。",
                "{company} 正在招聘多个岗位，点击查看。",
            ],
            "extra": ["退订请点此链接。", "更多职位请访问我们的网站。"],
        },
        "recruiter_spam": {
            "subject": ["想和您聊聊新的机会", "您的背景引起了我的注意"],
            "intro": ["{first} 您好：", "{first}，你好："],
            "core": [
                "我看到您的资料，想和您聊聊 {skill} 方向的机会。",
                "我们正在招聘多个岗位，您的经验很匹配。",
            ],
            "extra": ["即使暂时不合适，也希望能保持联系。", "方便的话请把简历发给我。"],
        },
        "newsletter": {
            "subject": ["求职周刊 第 128 期", "本周职场资讯"],
            "intro": ["{first} 您好："],
            "core": ["欢迎阅读《求职周刊》。", "本期我们聊聊如何谈薪资。"],
            "extra": ["转发给正在找工作的朋友吧。", "您收到本邮件是因为您订阅了我们的内容。"],
        },
        "account_security": {
            "subject": ["您的账户有新的登录", "安全提醒：异常活动"],
            "intro": ["{first} 您好："],
            "core": ["我们检测到您的账户在新设备上登录。", "有人请求重置您的账户密码。"],
            "extra": ["如果这不是您本人操作，请立即保护账户。", "请勿向任何人透露验证码。"],
        },
        "adversarial": {
            "subject": ["您的申请被拒了！", "支付失败提醒", "Re: 明天的面试"],
            "intro": ["{first} 您好："],
            "core": [
                "您的申请被拒了！——您在《面试大挑战》游戏中得分 2/5，游戏内的申请被拒绝，再试一次？",
                "很遗憾，签约奖金无法超过五千元——但我们很高兴地通知您，您已获得 {position} 岗位的录用！",
                "您的银行卡拒绝了这笔付款，请更新卡片以保持 {company} 会员资格。",
                "很遗憾您收藏的 {position} 岗位已招满——为您推荐五个类似职位。",
            ],
            "extra": ["回复 TD 退订。", "您的真实申请状态没有任何变化。"],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["保持联系", "您的资料"],
            "intro": ["{name} 您好："],
            "core": [
                "我们对您的印象不错，会在有合适职位时想到您。",
                "保持联系，团队下个季度可能还有需求。",
            ],
            "extra": ["随时欢迎与我联系。"],
        },
        "resume_on_file": {
            "subject": ["您的申请", "我们的人才库"],
            "intro": ["{name} 您好："],
            "core": ["您的简历已加入我们的人才库。", "我们会保留您的简历，有合适职位时与您联系。"],
            "extra": ["您无需再做任何操作。"],
        },
        "on_hold": {
            "subject": ["关于 {position} 岗位的进展", "{company} 招聘通知"],
            "intro": ["{first} 您好："],
            "core": ["我们决定暂停 {position} 岗位的招聘。", "该岗位因预算审批处于暂停状态。"],
            "extra": ["情况变化后我们会再联系您。"],
        },
        "assessment": {
            "subject": ["您的测评结果", "测评已完成"],
            "intro": ["{first} 您好："],
            "core": [
                "您的测评成绩为 62%，很遗憾未达到分数线。您可以重考一次。",
                "测评完成：8 题答对 4 题。招聘同事将尽快查看结果。",
            ],
            "extra": ["成绩可在候选人门户查看。"],
        },
    },
    "adv": {
        "subject": ["您的申请被拒了！", "支付失败提醒", "Re: 明天的面试", "拒信的艺术"],
        "intro": ["{first} 您好：", "{first}，你好："],
        "core": [
            (
                "您的申请被拒了！——您在《面试大挑战》游戏中得分 2/5，游戏内的申请被拒绝，再试一次？",
                "other",
            ),
            (
                "很遗憾，签约奖金无法超过五千元——但我们很高兴地通知您，您已获得 {position} 岗位的录用！",
                "opportunity",
            ),
            ("很遗憾本期内容较短：编辑忙着收集读者的拒信故事。", "other"),
            ("很遗憾您收藏的 {position} 岗位已招满——为您推荐五个类似职位。", "other"),
            (
                "您在 {company} 的面试已确认于周二 14:00 进行；很遗憾之前的日程工具出了故障。",
                "opportunity",
            ),
        ],
        "extra": ["回复 TD 退订。", "您的真实申请状态没有任何变化。", "完整条款见我们的网站。"],
    },
}

# Long untranslatable data strings: ruff format must not rejoin them past 120 columns.
# fmt: off
BANKS["hi"] = {
    "names": [
        "अनन्या शर्मा",
        "रोहित वर्मा",
        "प्रिया सिंह",
        "अमित पटेल",
        "नेहा गुप्ता",
        "विक्रम राव",
        "सुनीता देवी",
        "अर्जुन मेहता",
    ],
    "companies": [
        "टेकनोवा इंडिया",
        "आकाश डेटा",
        "स्वास्थ्य सेवा लिमिटेड",
        "उज्ज्वल फाइनेंस",
        "यात्रा लॉजिस्टिक्स",
        "मीडिया दर्पण",
        "शिक्षा विहार",
        "कृषि उन्नति",
    ],
    "positions": [
        "सीनियर बैकएंड इंजीनियर",
        "डेटा एनालिस्ट",
        "मार्केटिंग मैनेजर",
        "स्टाफ नर्स",
        "यूएक्स डिज़ाइनर",
        "अकाउंट एग्ज़ीक्यूटिव",
        "वित्त नियंत्रक",
        "प्रोजेक्ट मैनेजर",
    ],
    "skills": ["Python", "सप्लाई चेन", "B2B बिक्री", "डेटा विश्लेषण"],
    "greet": ["नमस्ते {name},", "प्रिय {name},", "सुप्रभात {name},"],
    "subject_rej": [
        "आपके आवेदन पर अपडेट",
        "{company} में आपके आवेदन की स्थिति",
        "{position} पद के लिए आपका आवेदन",
        "भर्ती प्रक्रिया का परिणाम",
    ],
    "decision": {
        "direct": [
            "हम आपके आवेदन को आगे नहीं बढ़ाएंगे।",
            "आपकी प्रोफ़ाइल की समीक्षा के बाद, हमने आगे बढ़ने का निर्णय नहीं लिया है।",
            "आपका चयन {position} पद के लिए नहीं हुआ है।",
            "हम आपको अगले चरण में शामिल नहीं कर रहे हैं।",
        ],
        "polite": [
            "सावधानीपूर्वक विचार करने के बाद, हमें यह बताते हुए खेद है कि हम आपकी उम्मीदवारी को आगे नहीं बढ़ाएंगे।",
            (
                "आपने इस प्रक्रिया में जो समय दिया, उसके लिए धन्यवाद, लेकिन हमने किसी और उम्मीदवार के साथ आगे बढ़ने "
                + "का निर्णय लिया है।"
            ),
            "हमें खेद है कि इस बार हम आपको {position} पद की पेशकश नहीं कर पाएंगे।",
            "आपकी पृष्ठभूमि जानकर अच्छा लगा; दुर्भाग्य से हमें आपका आवेदन अस्वीकार करना पड़ रहा है।",
        ],
        "brutal": [
            "नहीं। इस भूमिका के लिए आपका अनुभव पर्याप्त नहीं है।",
            "आप इस नौकरी के लिए योग्य नहीं हैं। कृपया दोबारा आवेदन न करें।",
            "हमने आपको अस्वीकार किया क्योंकि आपका पोर्टफोलियो कमज़ोर था और असाइनमेंट देर से जमा हुआ।",
            "हमने आपका आवेदन दो बार पढ़ा और दोनों बार जवाब नहीं था।",
        ],
        "vague": [
            "हमने किसी और दिशा में जाने का निर्णय लिया है।",
            "आंतरिक समीक्षा के बाद, हम आपकी प्रोफ़ाइल को आगे नहीं बढ़ा रहे हैं।",
            "आपका आवेदन बंद कर दिया गया है।",
            "हमारी आवश्यकताएं बदल गई हैं और हम आपके आवेदन को जारी नहीं रखेंगे।",
        ],
        "legal": [
            # fmt: off
            (
                "सूचित किया जाता है कि {company} ने आपके आवेदन पर विचार समाप्त कर दिया है और रोजगार का कोई प्रस्ताव "
                + "नहीं देगा।"
            ),
            # fmt: on
            "यह पत्र पुष्टि करता है कि उक्त पद के लिए आपकी उम्मीदवारी बिना किसी अग्रिम कार्रवाई के समाप्त कर दी गई है।",
            "कंपनी ने अपनी समीक्षा पूरी कर ली है और रोजगार का कोई प्रस्ताव नहीं दिया जाएगा; यह निर्णय अंतिम है।",
            "इस संचार में कुछ भी रोजगार अनुबंध या भविष्य के विचार की कोई प्रतिबद्धता नहीं बनाता।",
        ],
        "agency": [
            "हमारे ग्राहक ने अनुबंध भूमिका के लिए आपकी प्रोफ़ाइल पर आगे बढ़ने का निर्णय नहीं लिया है।",
            "हायरिंग मैनेजर ने आपका आवेदन देखा और दुर्भाग्य से उन्होंने मना कर दिया।",
            # fmt: off
            (
                "हमने आपको {company} में भेजा था और उनका जवाब नकारात्मक था - उन्होंने {skill} में अधिक अनुभव वाले "
                + "व्यक्ति को चुना।"
            ),
            # fmt: on
            "{position} पद पर बुरी खबर: ग्राहक ने किसी और उम्मीदवार को चुना।",
        ],
        "internal": [
            "आपको बताना चाहता था - टीम ने {position} पद के लिए आपको आगे बढ़ाने का निर्णय नहीं लिया है।",
            "हायरिंग मैनेजर से अभी-अभी जवाब आया: वे आपके आवेदन को आगे नहीं बढ़ा रहे हैं।",
            "मुझे यह कहते हुए खेद है कि पैनल ने किसी और उम्मीदवार को चुना।",
            "पद की ज़रूरतें बदल गई हैं और अब आप {position} के लिए दौड़ में नहीं हैं।",
        ],
        "ats": [
            "{position} पद (आईडी {id}) के लिए आपका आवेदन अगले चरण के लिए चयनित नहीं हुआ है।",
            "स्थिति अपडेट: चयनित नहीं। {company} में आपकी रुचि के लिए धन्यवाद।",
            "प्रिय आवेदक, यह एक स्वचालित सूचना है कि आपकी उम्मीदवारी बंद कर दी गई है।",
            "आपकी प्रोफ़ाइल हमारी ट्रैकिंग प्रणाली में अस्वीकृत स्थिति में ले जाई गई है।",
        ],
    },
    "context": [
        "इस पद के लिए हमें 600 से अधिक आवेदन प्राप्त हुए।",
        "यह एक प्रतिस्पर्धी चयन प्रक्रिया थी।",
        "पैनल ने शुक्रवार को बचे हुए उम्मीदवारों की समीक्षा की।",
        "कृपया जानें कि यह निर्णय जल्दबाज़ी में नहीं लिया गया।",
    ],
    "skill_line": [
        "{skill} में आपकी पृष्ठभूमि टीम की ज़रूरत के अनुरूप नहीं थी।",
        "इस भूमिका में {skill} का व्यावहारिक अनुभव अधिक चाहिए था।",
    ],
    "thanks": [
        "इस प्रक्रिया में दिए गए समय के लिए धन्यवाद।",
        "{company} में आपकी रुचि के लिए आभार।",
        "आपके धैर्य के लिए धन्यवाद।",
    ],
    "reopen": [
        "हम आपका रिज़्यूमे भविष्य के पदों के लिए सुरक्षित रखेंगे।",
        "नए पद खुलने पर आप दोबारा आवेदन कर सकते हैं।",
        "हम आपके लिए उपयुक्त अवसरों पर नज़र रखेंगे।",
    ],
    "closing": ["सादर,", "सधन्यवाद,", "भवदीय,", "शुभकामनाओं सहित,"],
    "titles": ["भर्ती अधिकारी", "टैलेंट अक्विज़िशन", "हायरिंग मैनेजर", "एचआर समन्वयक"],
    "neg": {
        "application_ack": {
            "subject": ["हमें आपका आवेदन मिल गया है", "आवेदन प्राप्त - {position}"],
            "intro": ["नमस्ते {first},", "प्रिय आवेदक,"],
            "core": [
                "{company} में {position} पद के लिए आवेदन करने के लिए धन्यवाद - हमें आपका आवेदन मिल गया।",
                "{position} पद (आईडी {id}) के लिए आपका आवेदन प्राप्त हुआ है और समीक्षा में है।",
            ],
            "extra": [
                "आप हमारे पोर्टल पर कभी भी स्थिति देख सकते हैं।",
                "यह मेलबॉक्स बिना निगरानी का है, कृपया उत्तर न दें।",
            ],
        },
        "interview_invite": {
            "subject": ["साक्षात्कार का निमंत्रण - {position}", "अगला कदम: बात करते हैं"],
            "intro": ["नमस्ते {first},", "प्रिय {name},"],
            "core": [
                "हम {position} पद के लिए 45 मिनट के साक्षात्कार के लिए आपको आमंत्रित करना चाहते हैं।",
                "टीम को आपका आवेदन पसंद आया और वे अगले चरण पर जाना चाहते हैं।",
            ],
            "extra": [
                "नीचे दिए लिंक से समय चुनें।",
                "साक्षात्कार में {skill} के आपके अनुभव पर चर्चा होगी।",
            ],
        },
        "offer_letter": {
            "subject": [
                "नियुक्ति प्रस्ताव - {company}",
                "हम आपको {position} पद की पेशकश करना चाहते हैं",
            ],
            "intro": ["प्रिय {name},"],
            "core": [
                "हमें {company} में {position} पद का प्रस्ताव देते हुए खुशी हो रही है।",
                "सफल अंतिम दौर के बाद, हम आपको टीम में शामिल करना चाहते हैं।",
            ],
            "extra": [
                "वेतन विवरण संलग्न है; कृपया {date} तक हस्ताक्षर करें।",
                "आपकी जॉइनिंग तिथि {date} होगी।",
            ],
        },
        "job_alert": {
            "subject": ["आपके लिए नई नौकरियां", "अनुशंसित नौकरियां"],
            "intro": ["नमस्ते {first},"],
            "core": [
                "आपकी प्रोफ़ाइल के आधार पर, हमने कुछ नई नौकरियां चुनी हैं।",
                "{company} कई पदों पर भर्ती कर रहा है; देखें।",
            ],
            "extra": [
                "सदस्यता समाप्त करने के लिए यहां क्लिक करें।",
                "अधिक नौकरियां हमारी वेबसाइट पर देखें।",
            ],
        },
        "recruiter_spam": {
            "subject": ["नए अवसरों पर बात करें", "आपकी प्रोफ़ाइल पर ध्यान गया"],
            "intro": ["नमस्ते {first},", "हाय {first},"],
            "core": [
                "मैंने आपकी प्रोफ़ाइल देखी और {skill} क्षेत्र के अवसरों पर बात करना चाहता हूं।",
                "हम कई पदों पर भर्ती कर रहे हैं और आपका अनुभव उपयुक्त लगता है।",
            ],
            "extra": [
                "समय उपयुक्त न हो तो भी संपर्क में रहना अच्छा रहेगा।",
                "सुविधा हो तो अपना बायोडेटा भेज दें।",
            ],
        },
        "newsletter": {
            "subject": ["करियर साप्ताहिक, अंक 128", "इस सप्ताह के करियर सुझाव"],
            "intro": ["नमस्ते {first},"],
            "core": [
                "करियर साप्ताहिक में आपका स्वागत है।",
                "इस अंक में हम वेतन वार्ता की बात करते हैं।",
            ],
            "extra": [
                "इसे नौकरी की तलाश में किसी मित्र को भेजें।",
                "आपको यह ईमेल इसलिए मिल रहा है क्योंकि आपने सदस्यता ली है।",
            ],
        },
        "account_security": {
            "subject": ["आपके खाते में नया साइन-इन", "सुरक्षा चेतावनी: असामान्य गतिविधि"],
            "intro": ["नमस्ते {first},"],
            "core": [
                "हमने आपके खाते में एक नए डिवाइस से साइन-इन देखा।",
                "किसी ने आपके खाते का पासवर्ड रीसेट करने का अनुरोध किया।",
            ],
            "extra": [
                "यदि यह आप नहीं थे, तो तुरंत अपना खाता सुरक्षित करें।",
                "अपने सत्यापन कोड किसी के साथ साझा न करें।",
            ],
        },
        "adversarial": {
            "subject": ["आपका आवेदन अस्वीकार हो गया!", "भुगतान अस्वीकृत", "Re: कल का साक्षात्कार"],
            "intro": ["नमस्ते {first},", "हाय {first},"],
            "core": [
                "आपका आवेदन अस्वीकार हो गया! - Interview Quest में आपने 5 में से 2 अंक पाए और गेम "
                "के भीतर आपका आवेदन अस्वीकार हुआ। फिर कोशिश "
                "करेंगे?",
                (
                    "दुर्भाग्य से साइनिंग बोनस पांच हज़ार से अधिक नहीं हो सकता -"
                    " लेकिन हमें {position} पद की पेशकश करते हुए खुशी हो रही है!"
                ),
                "आपके बैंक ने भुगतान अस्वीकार कर दिया। {company} की सदस्यता जारी रखने के लिए कार्ड अपडेट करें।",
                "दुर्भाग्य से आपके द्वारा सहेजा गया {position} पद भर गया है - यहां पांच समान पद हैं।",
            ],
            "extra": [
                "इन सुझावों से बाहर निकलने के लिए उत्तर दें।",
                "आपके वास्तविक आवेदन की स्थिति में कुछ नहीं बदला है।",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["संपर्क में रहें", "{company} में आपकी प्रोफ़ाइल"],
            "intro": ["नमस्ते {first},"],
            "core": [
                "आपकी प्रोफ़ाइल हमें दिलचस्प लगी और भविष्य की रिक्तियों के लिए हम आपको याद रखेंगे।",
                "संपर्क में रहें; अगली तिमाही में टीम की ज़रूरतें फिर हो सकती हैं।",
            ],
            "extra": ["कभी भी संपर्क कर सकते हैं।"],
        },
        "resume_on_file": {
            "subject": ["{company} में आपका आवेदन", "हमारा टैलेंट पूल"],
            "intro": ["प्रिय {name},"],
            "core": [
                "आपका रिज़्यूमे हमारे टैलेंट पूल में जोड़ दिया गया है।",
                "हम आपका रिज़्यूमे सुरक्षित रखेंगे और उपयुक्त पद आने पर संपर्क करेंगे।",
            ],
            "extra": ["आपको कोई और कदम उठाने की ज़रूरत नहीं है।"],
        },
        "on_hold": {
            "subject": ["{position} पद की स्थिति", "{company} भर्ती अपडेट"],
            "intro": ["नमस्ते {first},"],
            "core": [
                "हमने {position} पद की भर्ती रोकने का निर्णय लिया है।",
                "बजट अनुमोदन की प्रतीक्षा में यह पद रोक पर है।",
            ],
            "extra": ["स्थिति बदलने पर हम संपर्क करेंगे।"],
        },
        "assessment": {
            "subject": ["आपके मूल्यांकन के परिणाम", "मूल्यांकन पूर्ण"],
            "intro": ["नमस्ते {first},"],
            "core": [
                "आपका स्कोर 62% रहा; दुर्भाग्य से आप कटऑफ तक नहीं पहुंचे। आप एक बार फिर प्रयास कर सकते हैं।",
                "हमें खेद है कि आपका परिणाम {position} प्रक्रिया की कटऑफ से नीचे रहा।",
            ],
            "extra": ["परिणाम पोर्टल पर उपलब्ध हैं।"],
        },
    },
    "adv": {
        "subject": [
            "आपका आवेदन अस्वीकार हो गया!",
            "भुगतान अस्वीकृत",
            "Re: कल का साक्षात्कार",
            "अस्वीकृति पत्र की कला",
        ],
        "intro": ["नमस्ते {first},", "हाय {first},"],
        "core": [
            (
                "आपका आवेदन अस्वीकार हो गया! - Interview Quest में आपने 5 में से 2 अंक पाए और गेम "
                "के भीतर आपका आवेदन अस्वीकार हुआ। फिर कोशिश "
                "करेंगे?",
                "other",
            ),
            (
                (
                    "दुर्भाग्य से साइनिंग बोनस पांच हज़ार से अधिक नहीं हो सकता -"
                    " लेकिन हमें {position} पद की पेशकश करते हुए खुशी हो रही है!"
                ),
                "opportunity",
            ),
            (
                # fmt: off
                (
                    "हमें सूचित करते हुए खेद है कि इस अंक में सामग्री कम है: संपादक पाठकों की अस्वीकृति कहानियां जमा "
                    + "करने में व्यस्त थे।"
                ),
                # fmt: on
                "other",
            ),
            (
                "दुर्भाग्य से आपके द्वारा सहेजा गया {position} पद भर गया है - यहां पांच समान पद हैं।",
                "other",
            ),
            (
                # fmt: off
                (
                    "{company} में आपका साक्षात्कार मंगलवार 14:00 बजे तय है; पिछले शेड्यूलिंग टूल में गड़बड़ी के लिए "
                    + "खेद है।"
                ),
                # fmt: on
                "opportunity",
            ),
        ],
        "extra": [
            "इन सुझावों से बाहर निकलने के लिए उत्तर दें।",
            "आपके वास्तविक आवेदन की स्थिति में कुछ नहीं बदला है।",
            "पूरी शर्तें हमारी वेबसाइट पर हैं।",
        ],
    },
}
# fmt: on

BANKS["fr"] = {
    "names": [
        "Camille Moreau",
        "Julien Bernard",
        "Aicha Diallo",
        "Lucas Petit",
        "Elodie Girard",
        "Antoine Lefevre",
        "Sarah Benali",
        "Nicolas Roux",
    ],
    "companies": [
        "Innotech France",
        "Groupe Lumiere",
        "Sante Horizon",
        "Financiere du Rhone",
        "Logistique Atlantique",
        "Medias Aurore",
        "Conseil Bleu",
        "Retail Camino",
    ],
    "positions": [
        "Ingenieur Backend Senior",
        "Analyste de donnees",
        "Responsable marketing",
        "Infirmier/ere diplome/e",
        "Designer UX",
        "Charge/e de clientele",
        "Controleur de gestion",
        "Chef de projet",
    ],
    "skills": ["Python", "la chaine logistique", "la vente B2B", "la modelisation financiere"],
    "greet": ["Bonjour {name},", "Cher/Chere {name},", "Bonjour {first},"],
    "subject_rej": [
        "Suite a votre candidature",
        "Votre candidature chez {company}",
        "Concernant le poste de {position}",
        "Resultat du processus de recrutement",
    ],
    "decision": {
        "direct": [
            "Nous ne donnerons pas de suite a votre candidature.",
            "Apres examen de votre dossier, nous avons decide de ne pas poursuivre.",
            "Vous n'avez pas ete retenu/e pour le poste de {position}.",
            "Nous ne vous convions pas a la prochaine etape.",
        ],
        "polite": [
            "Apres mure reflexion, nous avons le regret de vous informer que nous ne donnerons pas "
            "de suite a votre "
            "candidature.",
            "Nous vous remercions du temps consacre au processus, mais avons decide de poursuivre "
            "avec un autre "
            "candidat.",
            "Nous sommes au regret de ne pas pouvoir vous proposer le poste de {position}.",
            "Ce fut un plaisir d'echanger avec vous ; malheureusement nous devons decliner votre candidature.",
        ],
        "brutal": [
            "Non. Votre experience est tres loin de ce que ce poste exige.",
            "Vous n'etes pas qualifie/e pour ce poste. Merci de ne pas postuler a nouveau.",
            "Nous vous avons refuse car votre portfolio etait faible et votre test est arrive en retard.",
            "Nous avons lu votre candidature deux fois et deux fois la reponse a ete non.",
        ],
        "vague": [
            "Nous avons decide d'aller dans une autre direction.",
            "Apres examen interne, nous ne poursuivons pas avec votre profil.",
            "Votre candidature a ete cloturee.",
            "Nos besoins ont evolue et nous ne donnerons pas de suite a votre candidature.",
        ],
        "legal": [
            "Nous vous informons que {company} a clos l'examen de votre candidature et ne "
            "formulera "
            "aucune offre "
            "d'emploi.",
            "La presente lettre confirme que votre candidature au poste susmentionne est close sans autre formalite.",
            "La Societe a termine son examen et aucune offre d'emploi ne sera formulee ; cette "
            "decision est "
            "definitive.",
            "Les presentes ne constituent ni contrat de travail ni engagement de reexamen futur.",
        ],
        "agency": [
            "Notre client a decide de ne pas poursuivre avec votre profil pour la mission.",
            "Le responsable a examine votre candidature et malheureusement a passe.",
            "Nous vous avons presente a {company} et leur reponse etait negative - ils ont choisi "
            "quelqu'un avec plus d'experience en "
            "{skill}.",
            "Mauvaise nouvelle pour le poste de {position} : le client a choisi un autre candidat.",
        ],
        "internal": [
            "Je tenais a vous faire un retour : l'equipe a decide de ne pas poursuivre avec vous "
            "pour le poste de "
            "{position}.",
            "Le manager vient de me confirmer qu'il ne donnait pas de suite a votre candidature.",
            "Je suis au regret de vous dire que le jury a retenu un autre candidat.",
            "Le poste a ete re-scoped et vous n'etes plus dans la course pour {position}.",
        ],
        "ats": [
            "Votre candidature au poste de {position} (ID {id}) n'a pas ete retenue pour la suite du processus.",
            "Mise a jour du statut : Non retenu/e. Merci de l'interet que vous portez a {company}.",
            "Madame, Monsieur, ceci est une notification automatique : votre candidature a ete cloturee.",
            "Votre profil est passe au statut Refuse dans notre systeme de suivi des candidatures.",
        ],
    },
    "context": [
        "Nous avons recu plus de 600 candidatures pour ce poste.",
        "Ce fut une selection tres competitive.",
        "Le jury s'est reuni vendredi pour examiner les candidatures restantes.",
        "Sachez que cette decision n'a pas ete prise a la legere.",
    ],
    "skill_line": [
        "Votre parcours en {skill} ne correspondait pas tout a fait aux besoins de l'equipe.",
        "Le poste exigeait davantage d'experience pratique en {skill}.",
    ],
    "thanks": [
        "Merci pour le temps que vous avez consacre au processus.",
        "Nous vous remercions de l'interet que vous portez a {company}.",
        "Merci de votre patience durant le processus.",
    ],
    "reopen": [
        "Nous conserverons votre CV pour de futures offres.",
        "Vous pourrez candidater a nouveau lorsque de nouveaux postes s'ouvriront.",
        "Nous resterons attentifs a des opportunites qui pourraient vous convenir.",
    ],
    "closing": ["Cordialement,", "Bien a vous,", "Sincerement,", "Salutations distinguees,"],
    "titles": [
        "Recruteur/se",
        "Talent Acquisition",
        "Responsable du recrutement",
        "Charge/e de RH",
    ],
    "neg": {
        "application_ack": {
            "subject": ["Nous avons recu votre candidature", "Candidature recue - {position}"],
            "intro": ["Bonjour {first},", "Madame, Monsieur,"],
            "core": [
                "Merci d'avoir postule au poste de {position} chez {company} - nous avons bien recu votre candidature.",
                "Votre candidature au poste de {position} (ID {id}) a ete recue et est en cours d'examen.",
            ],
            "extra": [
                "Vous pouvez suivre votre statut a tout moment sur notre portail.",
                "Cette boite n'est pas surveillee, merci de ne pas repondre.",
            ],
        },
        "interview_invite": {
            "subject": ["Invitation a un entretien - {position}", "Prochaine etape : parlons-en"],
            "intro": ["Bonjour {first},", "Cher/Chere {name},"],
            "core": [
                "Nous souhaiterions vous inviter a un entretien de 45 minutes pour le poste de {position}.",
                "L'equipe a apprecie votre candidature et souhaite passer a l'etape suivante.",
            ],
            "extra": [
                "Utilisez le lien ci-dessous pour choisir un creneau.",
                "L'entretien portera sur votre experience en {skill}.",
            ],
        },
        "offer_letter": {
            "subject": [
                "Offre d'emploi - {company}",
                "Nous souhaitons vous proposer le poste de {position}",
            ],
            "intro": ["Cher/Chere {name},"],
            "core": [
                "Nous avons le plaisir de vous proposer le poste de {position} chez {company}.",
                "Apres un dernier tour d'entretien reussi, nous souhaitons vous accueillir dans l'equipe.",
            ],
            "extra": [
                "Les details de remuneration sont joints ; merci de signer avant le {date}.",
                "Votre date de prise de poste est le {date}.",
            ],
        },
        "job_alert": {
            "subject": ["De nouvelles offres pour vous", "Offres recommandees"],
            "intro": ["Bonjour {first},"],
            "core": [
                "D'apres votre profil, nous vous avons selectionne quelques nouvelles offres.",
                "{company} recrute pour plusieurs postes ; jetez un oeil.",
            ],
            "extra": [
                "Pour vous desabonner, cliquez sur le lien ci-dessous.",
                "Retrouvez plus d'offres sur notre site.",
            ],
        },
        "recruiter_spam": {
            "subject": ["Parlons de nouvelles opportunites", "Votre profil a retenu mon attention"],
            "intro": ["Bonjour {first},", "Salut {first},"],
            "core": [
                "J'ai vu votre profil et j'aimerais vous parler d'opportunites dans le domaine de {skill}.",
                "Nous recrutons plusieurs postes et votre experience correspond bien.",
            ],
            "extra": [
                "Meme si le timing n'est pas ideal, restons en contact.",
                "Envoyez-moi votre CV si vous le souhaitez.",
            ],
        },
        "newsletter": {
            "subject": [
                "Le Hebdo du Recrutement, numero 128",
                "Vos conseils carriere de la semaine",
            ],
            "intro": ["Bonjour {first},"],
            "core": [
                "Bienvenue dans votre resume hebdomadaire du Hebdo du Recrutement.",
                "Cette semaine, comment negocier un package de relocation.",
            ],
            "extra": [
                "Transmettez ce message a quelqu'un en recherche active.",
                "Vous recevez cet email car vous etes abonne/e.",
            ],
        },
        "account_security": {
            "subject": [
                "Nouvelle connexion a votre compte",
                "Alerte de securite : activite inhabituelle",
            ],
            "intro": ["Bonjour {first},"],
            "core": [
                "Nous avons detecte une nouvelle connexion a votre compte depuis un nouvel appareil.",
                "Quelqu'un a demande la reinitialisation de votre mot de passe.",
            ],
            "extra": [
                "Si ce n'etait pas vous, securisez immediatement votre compte.",
                "Ne partagez jamais vos codes de verification.",
            ],
        },
        "adversarial": {
            "subject": [
                "Votre candidature a ete rejetee !",
                "Paiement refuse",
                "Re: votre entretien de demain",
            ],
            "intro": ["Bonjour {first},", "Salut {first},"],
            "core": [
                "Votre candidature a ete rejetee ! - vous avez obtenu 2 sur 5 a Interview Quest et "
                "votre candidature dans le jeu a ete rejetee. Nouvel essai "
                "?",
                "Malheureusement, nous ne pouvons pas depasser la prime de signature de 5 000 "
                "euros "
                "- mais nous sommes ravis de vous proposer le poste de {position} "
                "!",
                "Votre banque a refuse le paiement. Mettez a jour votre carte pour conserver votre "
                "abonnement Premium "
                "{company}.",
                "Malheureusement l'offre {position} que vous aviez enregistree chez {company} est "
                "pourvue - voici cinq offres "
                "similaires.",
            ],
            "extra": [
                "Repondez STOP pour vous desabonner.",
                "Rien n'a change concernant votre vraie candidature.",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["Restons en contact", "Votre profil chez {company}"],
            "intro": ["Bonjour {first},", "Cher/Chere {name},"],
            "core": [
                "Votre profil nous a interesses et nous garderons vos coordonnees pour de futures ouvertures.",
                "Restons en contact ; l'equipe pourrait de nouveau avoir des besons le prochain trimestre.",
            ],
            "extra": ["N'hesitez pas a me recontacter quand vous le souhaitez."],
        },
        "resume_on_file": {
            "subject": ["Votre candidature chez {company}", "Notre vivier de talents"],
            "intro": ["Cher/Chere {name},"],
            "core": [
                "Votre CV a ete ajoute a notre vivier de talents.",
                "Nous conserverons votre CV et vous contacterons si un poste correspondant s'ouvre.",
            ],
            "extra": ["Aucune action de votre part n'est necessaire."],
        },
        "on_hold": {
            "subject": ["Point sur le poste de {position}", "Actualites recrutement {company}"],
            "intro": ["Bonjour {first},"],
            "core": [
                "Nous avons decide de suspendre le recrutement pour le poste de {position}.",
                "Le poste de {position} est en pause dans l'attente de la validation budgetaire.",
            ],
            "extra": ["Nous reviendrons vers vous lorsque la situation evoluera."],
        },
        "assessment": {
            "subject": ["Vos resultats d'evaluation", "Evaluation terminee"],
            "intro": ["Bonjour {first},"],
            "core": [
                "Votre score est de 62 % ; malheureusement vous n'avez pas atteint le seuil. Vous "
                "pouvez repasser le test une "
                "fois.",
                "Nous regrettons que votre resultat soit en dessous du seuil requis pour le processus {position}.",
            ],
            "extra": ["Les resultats sont disponibles sur le portail candidat."],
        },
    },
    "adv": {
        "subject": [
            "Comment nous ecrasons les rejets a JobHuntConf",
            "Votre candidature a ete rejetee !",
            "Paiement refuse",
            "L'art de la lettre de refus",
        ],
        "intro": ["Bonjour {first},", "Salut {first},"],
        "core": [
            (
                "Votre candidature a ete rejetee ! - vous avez obtenu 2 sur 5 a Interview Quest et "
                "votre candidature dans le jeu a ete rejetee. Nouvel essai "
                "?",
                "other",
            ),
            (
                "Malheureusement, nous ne pouvons pas depasser la prime de signature - mais nous "
                "sommes ravis de vous proposer le poste de {position} "
                "!",
                "opportunity",
            ),
            (
                "Nous regrettons d'annoncer que ce numero est court : la redactrice etait occupe a "
                "collecter les histoires de refus de nos "
                "lecteurs.",
                "other",
            ),
            (
                "Malheureusement l'offre {position} que vous aviez enregistree chez {company} est "
                "pourvue - voici cinq offres "
                "similaires.",
                "other",
            ),
            (
                "Votre entretien pour le poste de {position} est confirme pour mardi 14h00 ; nous "
                "regrettons le dysfonctionnement precedent de "
                "l'outil.",
                "opportunity",
            ),
        ],
        "extra": [
            "Repondez STOP pour vous desabonner.",
            "Rien n'a change concernant votre vraie candidature.",
            "Conditions completes sur notre site.",
        ],
    },
}

BANKS["ar"] = {
    "names": [
        "محمد العلي",
        "فاطمة أحمد",
        "يوسف بن صالح",
        "ليلى منصور",
        "عمر الحسن",
        "نور الدين حمدي",
        "سارة الشمري",
        "خالد إبراهيم",
    ],
    "companies": [
        "تك نوفا",
        "مجموعة النور",
        "صحة الأفق",
        "المالية الرائدة",
        "لوجستيك الجنوب",
        "إعلام الشروق",
        "التعليم المتنور",
        "زراعة الغد",
    ],
    "positions": [
        "مهندس برمجيات أول",
        "محلل بيانات",
        "مدير تسويق",
        "ممرض مسجل",
        "مصمم تجربة المستخدم",
        "مسؤول مبيعات",
        "مراقب مالي",
        "مدير مشاريع",
    ],
    "skills": ["بايثون", "سلسلة الإمداد", "المبيعات", "التصميم"],
    "greet": ["مرحباً {name}،", "الأستاذ/ة {name} المحترم/ة،", "{name} العزيز/ة،"],
    "subject_rej": [
        "بخصوص طلب التوظيف الخاص بك",
        "تحديث حول طلبك لدى {company}",
        "نتيجة طلبك لوظيفة {position}",
        "تحديث حالة الطلب",
    ],
    "decision": {
        "direct": [
            "لن نقوم بمتابعة طلبك.",
            "بعد مراجعة ملفك، قررنا عدم المتابعة.",
            "لم يتم اختيارك لوظيفة {position}.",
            "لن ننتقل بك إلى المرحلة التالية.",
        ],
        "polite": [
            "بعد دراسة متأنية، يُؤسفنا إبلاغك بأننا لن نتابع طلبك.",
            "نشكر لك الوقت الذي استثمرته في العملية، لكننا قررنا المتابعة مع مرشح آخر.",
            "يُؤسفنا ألّا نتمكن من تقديم وظيفة {position} لك هذه المرة.",
            "يسعدنا أن تعرفنا على خلفيتك؛ وللأسف يجب أن نرفض طلبك.",
        ],
        "brutal": [
            "لا. خبرتك لا تقترب مما تتطلبه هذه الوظيفة.",
            "أنت غير مؤهل لهذه الوظيفة. من فضلك لا تتقدم مرة أخرى.",
            "رفضناك لأن ملفك الضعيف وواجبك المتأخر.",
            "قرأنا طلبك مرتين وفي المرتين كانت الإجابة لا.",
        ],
        "vague": [
            "قررنا أن نسير في اتجاه آخر.",
            "بعد مراجعة داخلية، لن نتابع ملفك.",
            "تم إغلاق طلبك.",
            "احتياجاتنا تغيرت ولن نستمر مع طلبك.",
        ],
        "legal": [
            "يُعلمكم أن {company} قد أنهت دراسة طلبكم ولن تُصدر أي عرض توظيف.",
            "يؤكد هذا الخط أن ترشحكم للمنصب المذكور قد انتهى دون مزيد من الإجراءات.",
            "أنهت الشركة مراجعتها ولن يصدر عرض توظيف؛ هذا القرار نهائي.",
            "لا يُعدّ هذا الاتصال عقد عمل ولا التزاماً بالنظر المستقبلي.",
        ],
        "agency": [
            "قرر عميلنا عدم المتابعة مع ملفك للوظيفة التعاقدية.",
            "راجع مدير التوظيف طلبك وللأسف لم يوافقوا.",
            "قدّمناك إلى {company} وكانت الإجابة سلبية؛ اختاروا شخصاً لديه خبرة أكبر في {skill}.",
            "أخبار سيئة حول وظيفة {position}: اختار العميل مرشحاً آخر.",
        ],
        "internal": [
            "أحببت أن أطلعك: قرر الفريق عدم المتابعة معك لوظيفة {position}.",
            "وصلني رد مدير التوظيف الآن: لن يتابعوا طلبك.",
            "يؤسفني أن أقول إن اللجنة اختارت مرشحاً آخر.",
            "تغيرت متطلبات الوظيفة ولم تعد ضمن سباق {position}.",
        ],
        "ats": [
            "لم يتم اختيار طلبك لوظيفة {position} (المعرف {id}) لمزيد من الدراسة.",
            "تحديث الحالة: غير مختار. شكراً لاهتمامك بـ {company}.",
            "مرشح عزيز، هذه رسالة آلية تُعلمك بأن ملفك قد أُغلق.",
            "تم نقل ملفك إلى حالة مرفوض في نظام تتبّع المتقدمين لدينا.",
        ],
    },
    "context": [
        "تلقينا أكثر من 600 طلب لهذه الوظيفة.",
        "كانت عملية اختيار شديدة التنافس.",
        "اجتمعت اللجنة يوم الجمعة لمراجعة المرشحين المتبقين.",
        "اعلم أن هذا القرار لم يُتخذ بتهور.",
    ],
    "skill_line": [
        "خلفيتك في {skill} لم تكن تماماً ما يحتاجه الفريق.",
        "كانت الوظيفة تتطلب خبرة عملية أعمق في {skill}.",
    ],
    "thanks": [
        "شكراً للوقت الذي خصصته للعملية.",
        "نشكر اهتمامك بـ {company}.",
        "شكراً لصبرك خلال العملية.",
    ],
    "reopen": [
        "سنحتفظ بسيرتك الذاتية للوظائف المستقبلية.",
        "يمكنك التقدم مرة أخرى عند فتح وظائف جديدة.",
        "سنراقب الفرص التي قد تناسبك.",
    ],
    "closing": ["مع أطيب التحيات،", "تحياتي،", "تفضلوا بقبول فائق الاحترام،", "شكراً،"],
    "titles": ["مسؤول توظيف", "استحواذ المواهب", "مدير التوظيف", "منسق الموارد البشرية"],
    "neg": {
        "application_ack": {
            "subject": ["استلمنا طلبك", "تم استلام الطلب - {position}"],
            "intro": ["مرحباً {first}،", "مرشح عزيز،"],
            "core": [
                "شكراً لتقدمك لوظيفة {position} لدى {company}؛ لقد استلمنا طلبك.",
                "تم استلام طلبك لوظيفة {position} (المعرف {id}) وهو الآن قيد المراجعة.",
            ],
            "extra": [
                "يمكنك متابعة حالتك في أي وقت عبر البوابة.",
                "هذه الصندوق غير مراقب، يرجى عدم الرد على هذه الرسالة.",
            ],
        },
        "interview_invite": {
            "subject": ["دعوة لمقابلة - {position}", "الخطوة التالية: لنتحدث"],
            "intro": ["مرحباً {first}،", "{name} العزيز/ة،"],
            "core": [
                "نودّ دعوتك لمقابلة مدتها 45 دقيقة لوظيفة {position}.",
                "أعجب الفريق طلبك ونود الانتقال إلى الخطوة التالية.",
            ],
            "extra": [
                "استخدم الرابط أدناه لاختيار موعد مع مدير التوظيف.",
                "ستتناول المقابلة خبرتك في {skill}.",
            ],
        },
        "offer_letter": {
            "subject": ["عرض توظيف - {company}", "نودّ عرض وظيفة {position} عليك"],
            "intro": ["{name} العزيز/ة،"],
            "core": [
                "يسرّنا عرض منصب {position} عليك لدى {company}.",
                "بعد جولة نهائية ناجحة، نودّ ضمك إلى الفريق.",
            ],
            "extra": ["تفاصيل الراتب مرفقة؛ يرجى التوقيع قبل {date}.", "تاريخ بدء عملك هو {date}."],
        },
        "job_alert": {
            "subject": ["وظائف جديدة لك", "وظائف مقترحة"],
            "intro": ["مرحباً {first}،"],
            "core": [
                "بناءً على ملفك، اخترنا لك بعض الوظائف الجديدة.",
                "{company} توظّف لعدة مناصب؛ ألقِ نظرة.",
            ],
            "extra": [
                "لإلغاء الاشتراك انقر الرابط أدناه.",
                "اعثر على المزيد من الوظائف على موقعنا.",
            ],
        },
        "recruiter_spam": {
            "subject": ["لنتحدث عن فرص جديدة", "لفت ملفك انتباهي"],
            "intro": ["مرحباً {first}،", "أهلاً {first}،"],
            "core": [
                "اطلعت على ملفك وأود التحدث معك عن فرص في مجال {skill}.",
                "نحن نوظف لعدة مناصب وخبرتك مناسبة.",
            ],
            "extra": [
                "حتى إن لم يكن التوقيت مناسباً، يسعدنا التواصل.",
                "إن أردت، أرسل لنا سيرتك الذاتية.",
            ],
        },
        "newsletter": {
            "subject": ["نشرة التوظيف الأسبوعية، العدد 128", "نصائح مهنية الأسبوع"],
            "intro": ["مرحباً {first}،"],
            "core": [
                "مرحباً بك في ملخصك الأسبوعي من نشرة التوظيف.",
                "هذا الأسبوع نتحدث عن التفاوض على راتب الانتقال.",
            ],
            "extra": ["أرسل النشرة لصديق يبحث عن عمل.", "تصلك هذه الرسالة لأنك مشترك في نشرتنا."],
        },
        "account_security": {
            "subject": ["تسجيل دخول جديد إلى حسابك", "تنبيه أمني: نشاط غير معتاد"],
            "intro": ["مرحباً {first}،"],
            "core": [
                "لاحظنا تسجيل دخول جديد إلى حسابك من جهاز جديد.",
                "طلب أحدهم إعادة تعيين كلمة مرور حسابك.",
            ],
            "extra": ["إن لم تكن أنت، أمن حسابك فوراً.", "لا تشارك رموز التحقق مع أي شخص."],
        },
        "adversarial": {
            "subject": ["تم رفض طلبك!", "تم رفض الدفعة", "Re: مقابلتك غداً"],
            "intro": ["مرحباً {first}،", "أهلاً {first}،"],
            "core": [
                "تم رفض طلبك! - حصلت على 2 من 5 في لعبة Interview Quest وتم رفض طلبك داخل اللعبة. جرّب مجدداً؟",
                "للأسف لا يمكننا تجاوز مكافأة التوقيع - لكننا سعداء بعرض وظيفة {position} عليك!",
                "رفضت بنكك الدفعة. حدّث بطاقتك للحفاظ على اشتراكك المميز لدى {company}.",
                "للأسف لوظيفة {position} التي حفظتها لدى {company} شُغّلت؛ هذه خمس وظائف مشابهة.",
            ],
            "extra": ["أرسل إيقاف لإلغاء هذه النصائح.", "لم يتغير شيء بخصوص طلبك الحقيقي."],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["لنبقَ على تواصل", "ملفك لدى {company}"],
            "intro": ["مرحباً {first}،"],
            "core": [
                "ملفك لفت انتباهنا وسنتذكرك للوظائف المستقبلية.",
                "لنبقَ على تواصل؛ قد يحتاج الفريق إلى تعيينات مجدداً الربع القادم.",
            ],
            "extra": ["لا تتردد في مراسلتي في أي وقت."],
        },
        "resume_on_file": {
            "subject": ["طلبك لدى {company}", "قاعدة المواهب"],
            "intro": ["{name} العزيز/ة،"],
            "core": [
                "تمت إضافة سيرتك الذاتية إلى قاعدة المواهب لدينا.",
                "سنحتفظ بسيرتك وسنتواصل معك عند وجود منصب مناسب.",
            ],
            "extra": ["لا حاجة لأي إجراء منك."],
        },
        "on_hold": {
            "subject": ["مستجدات وظيفة {position}", "تحديث التوظيف لدى {company}"],
            "intro": ["مرحباً {first}،"],
            "core": [
                "قررنا إيقاف التوظيف لوظيفة {position}.",
                "الوظيفة معلقة في انتظار اعتماد الميزانية.",
            ],
            "extra": ["سنتواصل معك عند تغير الوضع."],
        },
        "assessment": {
            "subject": ["نتائج التقييم الخاصة بك", "اكتمل التقييم"],
            "intro": ["مرحباً {first}،"],
            "core": [
                "نتيجتك 62%؛ للأسف لم تبلغ الحد المطلوب. يمكنك إعادة الاختبار مرة واحدة.",
                "يؤسفنا أن نتيجتك كانت دون الحد المطلوب لعملية {position}.",
            ],
            "extra": ["النتائج متاحة على بوابة المرشحين."],
        },
    },
    "adv": {
        "subject": [
            "كيف سحقنا الرفض في مؤتمر التوظيف",
            "تم رفض طلبك!",
            "تم رفض الدفعة",
            "فن رسالة الرفض",
        ],
        "intro": ["مرحباً {first}،", "أهلاً {first}،"],
        "core": [
            (
                "تم رفض طلبك! - حصلت على 2 من 5 في لعبة Interview Quest وتم رفض طلبك داخل اللعبة. جرّب مجدداً؟",
                "other",
            ),
            (
                "للأسف لا يمكننا تجاوز مكافأة التوقيع - لكننا سعداء بعرض وظيفة {position} عليك!",
                "opportunity",
            ),
            ("يؤسفنا أن هذا العدد قصير: المحررة كانت مشغولة بجمع قصص الرفض من قرائنا.", "other"),
            (
                "للأسف لوظيفة {position} التي حفظتها لدى {company} شُغّلت؛ هذه خمس وظائف مشابهة.",
                "other",
            ),
            (
                "مؤكد موعد مقابلتك لوظيفة {position} يوم الثلاثاء 14:00؛ نأسف لعطل أداة الجدولة السابقة.",
                "opportunity",
            ),
        ],
        "extra": [
            "أرسل إيقاف لإلغاء الاشتراك.",
            "لم يتغير شيء بخصوص طلبك الحقيقي.",
            "الشروط الكاملة على موقعنا.",
        ],
    },
}

# Long untranslatable data strings: ruff format must not rejoin them past 120 columns.
# fmt: off
BANKS["bn"] = {
    "names": [
        "রায়হান ইসলাম",
        "ফাতিমা আক্তার",
        "তানভীর হোসেন",
        "নুসরাত জাহান",
        "আরিফুল হক",
        "সাবিহা রহমান",
        "মাহমুদুল করিম",
        "তানিয়া সুলতানা",
    ],
    "companies": [
        "টেকনোভা বাংলাদেশ",
        "আকাশ ডেটা",
        "স্বাস্থ্যসেবা লিমিটেড",
        "উজ্জ্বল ফাইন্যান্স",
        "যাত্রা লজিস্টিক্স",
        "মিডিয়া দর্পণ",
        "শিক্ষা বিহার",
        "কৃষি উন্নয়ন",
    ],
    "positions": [
        "সিনিয়র ব্যাকএন্ড ইঞ্জিনিয়ার",
        "ডেটা অ্যানালিস্ট",
        "মার্কেটিং ম্যানেজার",
        "স্টাফ নার্স",
        "ইউএক্স ডিজাইনার",
        "অ্যাকাউন্ট এক্সিকিউটিভ",
        "আর্থিক নিয়ন্ত্রক",
        "প্রজেক্ট ম্যানেজার",
    ],
    "skills": ["পাইথন", "সাপ্লাই চেইন", "বি২বি বিক্রয়", "ডেটা বিশ্লেষণ"],
    "greet": ["প্রিয় {name},", "নমস্কার {name},", "{name} আপনাকে শুভেচ্ছা,"],
    "subject_rej": [
        "আপনার আবেদন সম্পর্কে আপডেট",
        "{company}-এ আপনার আবেদনের অবস্থা",
        "{position} পদের আবেদনের ফলাফল",
        "নিয়োগ প্রক্রিয়ার সিদ্ধান্ত",
    ],
    "decision": {
        "direct": [
            "আমরা আপনার আবেদন এগিয়ে নেব না।",
            "আপনার প্রোফাইল পর্যালোচনার পর আমরা এগিয়ে যাওয়ার সিদ্ধান্ত নিইনি।",
            "{position} পদের জন্য আপনাকে নির্বাচিত করা হয়নি।",
            "আমরা আপনাকে পরবর্তী ধাপে নিয়ে যাচ্ছি না।",
        ],
        "polite": [
            "যত্নসহকারে বিবেচনার পর, আমরা দুঃখের সাথে জানাচ্ছি যে আমরা আপনার প্রার্থিতা এগিয়ে নেব না।",
            # fmt: off
            (
                "প্রক্রিয়ায় আপনার দেওয়া সময়ের জন্য ধন্যবাদ, তবে আমরা অন্য প্রার্থীর সাথে এগিয়ে যাওয়ার সিদ্ধান্ত "
                + "নিয়েছি।"
            ),
            # fmt: on
            "দুঃখজনকভাবে এইবার আমরা আপনাকে {position} পদটি অফার করতে পারছি না।",
            "আপনার পটভূমি জেনে ভালো লাগল; দুর্ভাগ্যবশত আমাদের আপনার আবেদন প্রত্যাখ্যান করতে হচ্ছে।",
        ],
        "brutal": [
            "না। এই ভূমিকার জন্য আপনার অভিজ্ঞতা যথেষ্ট নয়।",
            "আপনি এই কাজের জন্য যোগ্য নন। অনুগ্রহ করে আবার আবেদন করবেন না।",
            "আপনার পোর্টফোলিয়ো দুর্বল এবং কাজ দেরিতে জমা হওয়ায় আমরা আপনাকে প্রত্যাখ্যান করেছি।",
            "আমরা আপনার আবেদন দুইবার পড়েছি এবং দুইবারই উত্তর ছিল না।",
        ],
        "vague": [
            "আমরা অন্য দিকে যাওয়ার সিদ্ধান্ত নিয়েছি।",
            "অভ্যন্তরীণ পর্যালোচনার পর আমরা আপনার প্রোফাইল এগিয়ে নেব না।",
            "আপনার আবেদন বন্ধ করা হয়েছে।",
            "আমাদের চাহিদা পরিবর্তিত হয়েছে এবং আমরা আপনার আবেদন চালিয়ে যাব না।",
        ],
        "legal": [
            "জানানো যাচ্ছে যে {company} আপনার আবেদনের বিবেচনা শেষ করেছে এবং কোনো নিয়োগ প্রস্তাব দেবে না।",
            "এই চিঠি নিশ্চিত করে যে উক্ত পদের জন্য আপনার প্রার্থিতা কোনো অতিরিক্ত ব্যবস্থা ছাড়াই শেষ হয়েছে।",
            "কোম্পানি তার পর্যালোচনা সম্পন্ন করেছে এবং কোনো নিয়োগ প্রস্তাব দেওয়া হবে না; এই সিদ্ধান্ত চূড়ান্ত।",
            "এই যোগাযোগে কিছুই কর্মসংস্থান চুক্তি বা ভবিষ্যতের বিবেচনার কোনো প্রতিশ্রুতি নয়।",
        ],
        "agency": [
            "আমাদের ক্লায়েন্ট চুক্তিভিত্তিক ভূমিকার জন্য আপনার প্রোফাইল এগিয়ে নেওয়ার সিদ্ধান্ত নেয়নি।",
            "হায়রিং ম্যানেজার আপনার আবেদন দেখেছেন এবং দুর্ভাগ্যবশত তিনি রাজি হননি।",
            (
                "আমরা আপনাকে {company}-এ পাঠিয়েছিলাম, তাদের উত্তর ছিল নেতিবা"
                "চক - তারা {skill} এ বেশি অভিজ্ঞতাসম্পন্ন কেউকে বেছে নিয়েছে।"
            ),
            "{position} পদ নিয়ে খারাপ খবর: ক্লায়েন্ট অন্য প্রার্থীকে বেছে নিয়েছে।",
        ],
        "internal": [
            "আপনাকে জানাতে চেয়েছিলাম - দল {position} পদের জন্য আপনাকে এগিয়ে নেওয়ার সিদ্ধান্ত নেয়নি।",
            "হায়রিং ম্যানেজারের কাছ থেকে এইমাত্র উত্তর এল: তারা আপনার আবেদন এগিয়ে নেবে না।",
            "দুঃখের সাথে বলছি প্যানেল অন্য প্রার্থীকে বেছে নিয়েছে।",
            "পদের প্রয়োজন বদলে গেছে এবং আপনি আর {position} এর দৌড়ে নেই।",
        ],
        "ats": [
            "{position} পদের (আইডি {id}) জন্য আপনার আবেদন পরবর্তী বিবেচনার জন্য নির্বাচিত হয়নি।",
            "স্ট্যাটাস আপডেট: নির্বাচিত হননি। {company}-এ আপনার আগ্রহের জন্য ধন্যবাদ।",
            "প্রিয় আবেদনকারী, এটি একটি স্বয়ংক্রিয় বিজ্ঞপ্তি যে আপনার প্রার্থিতা বন্ধ করা হয়েছে।",
            "আপনার প্রোফাইল আমাদের ট্র্যাকিং সিস্টেমে প্রত্যাখ্যাত অবস্থায় সরানো হয়েছে।",
        ],
    },
    "context": [
        "এই পদের জন্য আমরা ৬০০-এর বেশি আবেদন পেয়েছি।",
        "এটি অত্যন্ত প্রতিযোগিতামূলক নির্বাচন ছিল।",
        "প্যানেল শুক্রবার বাকি প্রার্থীদের পর্যালোচনা করেছে।",
        "জানুন এই সিদ্ধান্ত হঠকারিতায় নেওয়া হয়নি।",
    ],
    "skill_line": [
        "{skill} এ আপনার পটভূমি দলের প্রয়োজনের সাথে ঠিক মেলেনি।",
        "এই ভূমিকায় {skill} এ বাস্তব অভিজ্ঞতা বেশি প্রয়োজন ছিল।",
    ],
    "thanks": [
        "প্রক্রিয়ায় দেওয়া সময়ের জন্য ধন্যবাদ।",
        "{company}-এ আপনার আগ্রহের জন্য কৃতজ্ঞতা।",
        "আপনার ধৈর্যের জন্য ধন্যবাদ।",
    ],
    "reopen": [
        "আমরা ভবিষ্যতের পদের জন্য আপনার সিভি সংরক্ষণ করব।",
        "নতুন পদ খুললে আপনি আবার আবেদন করতে পারেন।",
        "আমরা আপনার জন্য উপযুক্ত সুযোগ খেয়াল রাখব।",
    ],
    "closing": ["শুভেচ্ছাসহ,", "ধন্যবাদ,", "সবিনয় নিবেদন,", "শুভকামনাসহ,"],
    "titles": [
        "নিয়োগ কর্মকর্তা",
        "ট্যালেন্ট অ্যাকুইজিশন",
        "হায়রিং ম্যানেজার",
        "এইচআর সমন্বয়কারী",
    ],
    "neg": {
        "application_ack": {
            "subject": ["আপনার আবেদন পেয়েছি", "আবেদন গৃহীত - {position}"],
            "intro": ["প্রিয় {first},", "প্রিয় আবেদনকারী,"],
            "core": [
                "{company}-এ {position} পদে আবেদনের জন্য ধন্যবাদ - আমরা আপনার আবেদন পেয়েছি।",
                "{position} পদের (আইডি {id}) আপনার আবেদন গৃহীত হয়েছে এবং পর্যালোচনায় রয়েছে।",
            ],
            "extra": [
                "আপনি যেকোনো সময় পোর্টালে অবস্থা দেখতে পারেন।",
                "এই মেইলবক্স তত্ত্বাবধানহীন, অনুগ্রহ করে উত্তর দেবেন না।",
            ],
        },
        "interview_invite": {
            "subject": ["সাক্ষাৎকারের আমন্ত্রণ - {position}", "পরবর্তী ধাপ: কথা বলি"],
            "intro": ["প্রিয় {first},", "{name},"],
            "core": [
                "আমরা {position} পদের জন্য ৪৫ মিনিটের সাক্ষাৎকারে আপনাকে আমন্ত্রণ জানাতে চাই।",
                "দল আপনার আবেদন পছন্দ করেছে এবং পরবর্তী ধাপে যেতে চায়।",
            ],
            "extra": [
                "নিচের লিংক থেকে সময় বেছে নিন।",
                "সাক্ষাৎকারে {skill} এ আপনার অভিজ্ঞতা নিয়ে আলোচনা হবে।",
            ],
        },
        "offer_letter": {
            "subject": ["নিয়োগ প্রস্তাব - {company}", "আমরা আপনাকে {position} পদটি অফার করতে চাই"],
            "intro": ["প্রিয় {name},"],
            "core": [
                "{company}-এ {position} পদের প্রস্তাব দিতে পেরে আমরা আনন্দিত।",
                "সফল চূড়ান্ত পর্বের পর আমরা আপনাকে দলে নিতে চাই।",
            ],
            "extra": [
                "বেতনের বিবরণ সংযুক্ত; অনুগ্রহ করে {date} তারিখের মধ্যে স্বাক্ষর করুন।",
                "আপনার যোগদানের তারিখ {date}।",
            ],
        },
        "job_alert": {
            "subject": ["আপনার জন্য নতুন চাকরি", "প্রস্তাবিত চাকরি"],
            "intro": ["প্রিয় {first},"],
            "core": [
                "আপনার প্রোফাইলের ভিত্তিতে আমরা কয়েকটি নতুন চাকরি বেছে দিয়েছি।",
                "{company} একাধিক পদে নিয়োগ দিচ্ছে; দেখুন।",
            ],
            "extra": ["আনসাবস্ক্রাইব করতে নিচের লিংকে ক্লিক করুন।", "আরও চাকরি আমাদের ওয়েবসাইটে।"],
        },
        "recruiter_spam": {
            "subject": ["নতুন সুযোগ নিয়ে কথা বলি", "আপনার প্রোফাইল নজরে পড়েছে"],
            "intro": ["প্রিয় {first},", "হাই {first},"],
            "core": [
                "আমি আপনার প্রোফাইল দেখেছি এবং {skill} ক্ষেত্রের সুযোগ নিয়ে কথা বলতে চাই।",
                "আমরা একাধিক পদে নিয়োগ দিচ্ছি এবং আপনার অভিজ্ঞতা মানানসই।",
            ],
            "extra": [
                "সময় উপযুক্ত না হলেও যোগাযোগে থাকলে ভালো হয়।",
                "সুবিধা হলে আপনার সিভি পাঠান।",
            ],
        },
        "newsletter": {
            "subject": ["ক্যারিয়ার সাপ্তাহিক, সংখ্যা ১২৮", "এ সপ্তাহের ক্যারিয়ার পরামর্শ"],
            "intro": ["প্রিয় {first},"],
            "core": [
                "ক্যারিয়ার সাপ্তাহিকে আপনাকে স্বাগতম।",
                "এ সংখ্যায় আমরা বেতন আলোচনা নিয়ে কথা বলছি।",
            ],
            "extra": [
                "চাকরি খুঁজছেন এমন বন্ধুকে এটি পাঠান।",
                "আপনি সাবস্ক্রাইব করায় এই ইমেইল পাচ্ছেন।",
            ],
        },
        "account_security": {
            "subject": [
                "আপনার অ্যাকাউন্টে নতুন সাইন-ইন",
                "নিরাপত্তা সতর্কতা: অস্বাভাবিক কার্যকলাপ",
            ],
            "intro": ["প্রিয় {first},"],
            "core": [
                "আমরা নতুন ডিভাইস থেকে আপনার অ্যাকাউন্টে সাইন-ইন লক্ষ্য করেছি।",
                "কেউ আপনার অ্যাকাউন্টের পাসওয়ার্ড রিসেটের অনুরোধ করেছে।",
            ],
            "extra": [
                "এটি আপনি না হলে অবিলম্বে অ্যাকাউন্ট সুরক্ষিত করুন।",
                "আপনার যাচাইকরণ কোড কারও সাথে শেয়ার করবেন না।",
            ],
        },
        "adversarial": {
            "subject": [
                "আপনার আবেদন প্রত্যাখ্যাত হয়েছে!",
                "পেমেন্ট প্রত্যাখ্যাত",
                "Re: আগামীকালের সাক্ষাৎকার",
            ],
            "intro": ["প্রিয় {first},", "হাই {first},"],
            "core": [
                "আপনার আবেদন প্রত্যাখ্যাত হয়েছে! - Interview Quest-এ আপনি ৫-এর মধ্যে ২ পেয়েছেন "
                "এবং গেমের ভেতরে আপনার আবেদন প্রত্যাখ্যাত হয়েছে। আবার চেষ্টা "
                "করবেন?",
                (
                    "দুর্ভাগ্যবশত সাইনিং বোনাস পাঁচ হাজারের বেশি হতে পারবে না - কিন্তু আমরা আনন্দের সাথে {position} "
                    + "পদের প্রস্তাব দিচ্ছি!"
                ),
                "আপনার ব্যাংক পেমেন্ট প্রত্যাখ্যান করেছে। {company}-এর সদস্যতা বজায় রাখতে কার্ড আপডেট করুন।",
                "দুর্ভাগ্যবশত আপনি সংরক্ষিত {position} পদটি পূর্ণ হয়ে গেছে - এখানে পাঁচটি অনুরূপ পদ রইল।",
            ],
            "extra": [
                "এই পরামর্শ থেকে বের হতে উত্তর দিন।",
                "আপনার বাস্তব আবেদনের অবস্থায় কিছুই বদলায়নি।",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["যোগাযোগে থাকুন", "{company}-এ আপনার প্রোফাইল"],
            "intro": ["প্রিয় {first},"],
            "core": [
                "আপনার প্রোফাইল আমাদের পছন্দ হয়েছে এবং ভবিষ্যতের পদের জন্য আমরা আপনাকে মনে রাখব।",
                "যোগাযোগে থাকুন; আগামী ত্রৈমাসিকে দলের আবার প্রয়োজন হতে পারে।",
            ],
            "extra": ["যেকোনো সময় আমাকে লিখুন।"],
        },
        "resume_on_file": {
            "subject": ["{company}-এ আপনার আবেদন", "আমাদের ট্যালেন্ট পুল"],
            "intro": ["প্রিয় {name},"],
            "core": [
                "আপনার সিভি আমাদের ট্যালেন্ট পুলে যুক্ত হয়েছে।",
                "আমরা আপনার সিভি সংরক্ষণ করব এবং উপযুক্ত পদ এলে যোগাযোগ করব।",
            ],
            "extra": ["আপনার কোনো পদক্ষেপের প্রয়োজন নেই।"],
        },
        "on_hold": {
            "subject": ["{position} পদের সর্বশেষ অবস্থা", "{company} নিয়োগ আপডেট"],
            "intro": ["প্রিয় {first},"],
            "core": [
                "আমরা {position} পদের নিয়োগ স্থগিত করার সিদ্ধান্ত নিয়েছি।",
                "বাজেট অনুমোদনের অপেক্ষায় এই পদ স্থগিত রয়েছে।",
            ],
            "extra": ["অবস্থা বদলালে আমরা যোগাযোগ করব।"],
        },
        "assessment": {
            "subject": ["আপনার মূল্যায়নের ফলাফল", "মূল্যায়ন সম্পন্ন"],
            "intro": ["প্রিয় {first},"],
            "core": [
                "আপনার স্কোর ৬২%; দুর্ভাগ্যবশত আপনি কাটঅফ ছুঁতে পারেননি। আপনি একবার পুনরায় চেষ্টা করতে পারেন।",
                "দুঃখজনকভাবে আপনার ফলাফল {position} প্রক্রিয়ার কাটঅফের নিচে রয়েছে।",
            ],
            "extra": ["ফলাফল পোর্টালে পাওয়া যাবে।"],
        },
    },
    "adv": {
        "subject": [
            "আমরা কীভাবে প্রত্যাখ্যান জয় করেছি",
            "আপনার আবেদন প্রত্যাখ্যাত হয়েছে!",
            "পেমেন্ট প্রত্যাখ্যাত",
            "প্রত্যাখ্যান পত্রের শিল্প",
        ],
        "intro": ["প্রিয় {first},", "হাই {first},"],
        "core": [
            (
                "আপনার আবেদন প্রত্যাখ্যাত হয়েছে! - Interview Quest-এ আপনি ৫-এর মধ্যে ২ পেয়েছেন "
                "এবং গেমের ভেতরে আপনার আবেদন প্রত্যাখ্যাত হয়েছে। আবার চেষ্টা "
                "করবেন?",
                "other",
            ),
            (
                (
                    "দুর্ভাগ্যবশত সাইনিং বোনাস পাঁচ হাজারের বেশি হতে পারবে না - কিন্তু আমরা আনন্দের সাথে {position} "
                    + "পদের প্রস্তাব দিচ্ছি!"
                ),
                "opportunity",
            ),
            (
                "আমরা জানাতে দুখিত এই সংখ্যা ছোট হয়েছে: সম্পাদক পাঠকদের প্রত্যাখ্যান গল্প সংগ্রহে ব্যস্ত ছিলেন।",
                "other",
            ),
            (
                "দুর্ভাগ্যবশত আপনি সংরক্ষিত {position} পদটি পূর্ণ হয়ে গেছে - এখানে পাঁচটি অনুরূপ পদ রইল।",
                "other",
            ),
            (
                "{company}-এ আপনার সাক্ষাৎকার মঙ্গলবার ১৪:০০ নিশ্চিত; আগের শিডিউলিং টুলের ত্রুটির জন্য আমরা দুখিত।",
                "opportunity",
            ),
        ],
        "extra": [
            "এই পরামর্শ থেকে বের হতে উত্তর দিন।",
            "আপনার বাস্তব আবেদনের অবস্থায় কিছুই বদলায়নি।",
            "সম্পূর্ণ শর্তাবলি আমাদের ওয়েবসাইটে।",
        ],
    },
}
# fmt: on

BANKS["pt"] = {
    "names": [
        "Ana Beatriz Costa",
        "Joao Pereira",
        "Mariana Souza",
        "Lucas Oliveira",
        "Camila Ribeiro",
        "Rafael Almeida",
        "Juliana Lima",
        "Pedro Carvalho",
    ],
    "companies": [
        "TecNova Brasil",
        "Grupo Horizonte",
        "Saude Integral",
        "Financeira Aurora",
        "Logistica do Sul",
        "Midia Verde",
        "Consultoria Azul",
        "Varejo Caminho",
    ],
    "positions": [
        "Engenheiro Backend Senior",
        "Analista de Dados",
        "Gerente de Marketing",
        "Enfermeiro(a) Registrado(a)",
        "Designer UX",
        "Executivo de Contas",
        "Controller Financeiro",
        "Gerente de Projetos",
    ],
    "skills": ["Python", "cadeia de suprimentos", "vendas B2B", "modelagem financeira"],
    "greet": ["Ola {name},", "Prezado(a) {name},", "Bom dia {name},"],
    "subject_rej": [
        "Atualizacao sobre sua candidatura",
        "Sua candidatura na {company}",
        "Sobre a vaga de {position}",
        "Resultado do processo seletivo",
    ],
    "decision": {
        "direct": [
            "Nao seguiremos com a sua candidatura.",
            "Apos analise do seu perfil, decidimos nao prosseguir.",
            "Voce nao foi selecionado(a) para a vaga de {position}.",
            "Nao estaremos levando voce a proxima etapa.",
        ],
        "polite": [
            "Apos cuidadosa consideracao, lamentamos informar que nao daremos continuidade a sua candidatura.",
            "Agradecemos o tempo dedicado ao processo, mas decidimos seguir com outro candidato.",
            "Lamentavelmente nao poderemos oferecer a vaga de {position} a voce nesta ocasiao.",
            "Foi um prazer conhecer sua trajetoria; infelizmente precisamos declinar sua candidatura.",
        ],
        "brutal": [
            "Nao. Sua experiencia esta longe do que esta vaga exige.",
            "Voce nao esta qualificado(a) para esta vaga. Por favor, nao se candidate novamente.",
            "Rejeitamos voce porque seu portfolio foi fraco e o teste entregue com atraso.",
            "Lemos sua candidatura duas vezes e as duas vezes a resposta foi nao.",
        ],
        "vague": [
            "Decidimos seguir em outra direcao.",
            "Apos revisao interna, nao prosseguiremos com o seu perfil.",
            "Sua candidatura foi encerrada.",
            "Nossas necessidades mudaram e nao daremos continuidade a sua candidatura.",
        ],
        "legal": [
            "Ficamos em lhe informar que a {company} concluiu a analise da sua candidatura e nao "
            "emitira oferta de "
            "emprego.",
            "Esta carta confirma que sua candidatura a posicao mencionada foi concluida sem mais tramites.",
            "A Sociedade concluiu sua analise e nenhuma oferta de emprego sera feita; esta decisao e final.",
            "Nada nesta comunicacao constitui contrato de trabalho ou compromisso de analise futura.",
        ],
        "agency": [
            "Nosso cliente decidiu nao prosseguir com o seu perfil para a vaga por contrato.",
            "O gerente analisou sua candidatura e infelizmente nao avancou.",
            "Apresentamos voce a {company} e a resposta foi negativa - escolheram alguem com mais "
            "experiencia em "
            "{skill}.",
            "Noticias ruins sobre a vaga de {position}: o cliente escolheu outro candidato.",
        ],
        "internal": [
            "Queria te atualizar: a equipe decidiu nao seguir com voce para a vaga de {position}.",
            "Acabei de falar com o gerente de contratacao: eles nao vao avancar com a sua candidatura.",
            "Lamento dizer que o painel escolheu outro candidato.",
            "A vaga foi reescopada e voce nao esta mais na corrida por {position}.",
        ],
        "ats": [
            "Sua candidatura para a vaga de {position} (ID {id}) nao foi selecionada para prosseguimento.",
            "Atualizacao de status: Nao selecionado(a). Obrigado pelo seu interesse na {company}.",
            "Prezado(a) candidato(a), esta e uma notificacao automatica de que sua candidatura foi encerrada.",
            "Seu perfil foi movido para o status Rejeitado no nosso sistema de acompanhamento.",
        ],
    },
    "context": [
        "Recebemos mais de 600 candidaturas para esta vaga.",
        "Foi um processo seletivo bem competitivo.",
        "O painel se reuniu na sexta-feira para avaliar os candidatos restantes.",
        "Saiba que esta decisao nao foi tomada de forma leviana.",
    ],
    "skill_line": [
        "Sua experiencia em {skill} nao era exatamente o que a equipe precisava.",
        "A vaga exigia mais experiencia pratica em {skill}.",
    ],
    "thanks": [
        "Obrigado pelo tempo dedicado ao processo.",
        "Agradecemos seu interesse na {company}.",
        "Obrigado pela paciencia durante o processo.",
    ],
    "reopen": [
        "Vamos manter seu curriculo para futuras vagas.",
        "Voce pode se candidatar novamente quando novas vagas abrirem.",
        "Ficaremos atentos a vagas que possam lhe interessar.",
    ],
    "closing": ["Atenciosamente,", "Cordialmente,", "Abraços,", "Com os melhores cumprimentos,"],
    "titles": [
        "Recrutador(a)",
        "Talent Acquisition",
        "Gerente de Contratacao",
        "Coordenador(a) de RH",
    ],
    "neg": {
        "application_ack": {
            "subject": ["Recebemos sua candidatura", "Candidatura recebida - {position}"],
            "intro": ["Ola {first},", "Prezado(a) candidato(a),"],
            "core": [
                "Obrigado por se candidatar a vaga de {position} na {company} - recebemos sua candidatura.",
                "Sua candidatura para a vaga de {position} (ID {id}) foi recebida e esta em analise.",
            ],
            "extra": [
                "Voce pode acompanhar seu status no portal de candidatos.",
                "Esta caixa nao e monitorada; por favor, nao responda.",
            ],
        },
        "interview_invite": {
            "subject": ["Convite para entrevista - {position}", "Proxima etapa: vamos conversar"],
            "intro": ["Ola {first},", "Prezado(a) {name},"],
            "core": [
                "Gostaríamos de convida-lo(a) para uma entrevista de 45 minutos para a vaga de {position}.",
                "A equipe gostou da sua candidatura e gostaria de avancar para a proxima etapa.",
            ],
            "extra": [
                "Use o link abaixo para escolher um horario.",
                "A entrevista abordara sua experiencia em {skill}.",
            ],
        },
        "offer_letter": {
            "subject": ["Oferta de emprego - {company}", "Queremos oferecer a vaga de {position}"],
            "intro": ["Prezado(a) {name},"],
            "core": [
                "Temos o prazer de oferecer-lhe o cargo de {position} na {company}.",
                "Apos uma ultima rodada bem-sucedida, queremos integrar voce a equipe.",
            ],
            "extra": [
                "Os detalhes de remuneracao estao anexados; assine ate {date}.",
                "Sua data de inicio sera {date}.",
            ],
        },
        "job_alert": {
            "subject": ["Novas vagas para voce", "Vagas recomendadas"],
            "intro": ["Ola {first},"],
            "core": [
                "Com base no seu perfil, selecionamos algumas novas vagas.",
                "A {company} esta contratando para varias vagas; confira.",
            ],
            "extra": [
                "Para cancelar, clique no link abaixo.",
                "Encontre mais vagas no nosso site.",
            ],
        },
        "recruiter_spam": {
            "subject": ["Vamos conversar sobre oportunidades", "Seu perfil chamou minha atencao"],
            "intro": ["Ola {first},", "Oi {first},"],
            "core": [
                "Vi seu perfil e gostaria de falar sobre oportunidades na area de {skill}.",
                "Estamos contratando para varias vagas e sua experiencia se encaixa bem.",
            ],
            "extra": [
                "Mesmo que o timing nao seja ideal, vamos manter contato.",
                "Se quiser, me envie seu curriculo.",
            ],
        },
        "newsletter": {
            "subject": ["Semanal de Carreira, edicao 128", "Suas dicas de carreira da semana"],
            "intro": ["Ola {first},"],
            "core": [
                "Bem-vindo ao seu resumo semanal do Semanal de Carreira.",
                "Esta semana falamos sobre como negociar um pacote de relocacao.",
            ],
            "extra": [
                "Encaminhe este email para alguem em busca ativa.",
                "Voce recebe este email porque se inscreveu na nossa lista.",
            ],
        },
        "account_security": {
            "subject": ["Novo acesso a sua conta", "Alerta de seguranca: atividade incomum"],
            "intro": ["Ola {first},"],
            "core": [
                "Detectamos um novo acesso a sua conta a partir de um novo dispositivo.",
                "Alguem solicitou a redefinicao da senha da sua conta.",
            ],
            "extra": [
                "Se nao foi voce, proteja sua conta imediatamente.",
                "Nunca compartilhe seus codigos de verificacao.",
            ],
        },
        "adversarial": {
            "subject": [
                "Sua candidatura foi rejeitada!",
                "Pagamento recusado",
                "Re: sua entrevista de amanha",
            ],
            "intro": ["Ola {first},", "Oi {first},"],
            "core": [
                "Sua candidatura foi rejeitada! - voce marcou 2 de 5 no Interview Quest e sua "
                "candidatura dentro do jogo foi rejeitada. Tenta de "
                "novo?",
                "Infelizmente nao podemos ultrapassar o bonus de assinatura - mas estamos felizes "
                "em oferecer a vaga de "
                "{position}!",
                "Seu banco recusou o pagamento. Atualize seu cartao para manter a assinatura Premium na {company}.",
                "Infelizmente a vaga de {position} que voce salvou na {company} foi preenchida; "
                "veja cinco vagas "
                "parecidas.",
            ],
            "extra": [
                "Responda SAIR para cancelar estas dicas.",
                "Nada mudou sobre a sua candidatura real.",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["Vamos manter contato", "Seu perfil na {company}"],
            "intro": ["Ola {first},", "Prezado(a) {name},"],
            "core": [
                "Seu perfil nos chamou atencao e vamos guarda-lo para futuras vagas.",
                "Vamos manter contato; a equipe pode ter novas necessidades no proximo trimestre.",
            ],
            "extra": ["Fique a vontade para me escrever quando quiser."],
        },
        "resume_on_file": {
            "subject": ["Sua candidatura na {company}", "Nosso banco de talentos"],
            "intro": ["Prezado(a) {name},"],
            "core": [
                "Seu curriculo foi adicionado ao nosso banco de talentos.",
                "Vamos manter seu curriculo e entraremos em contato se surgir uma vaga adequada.",
            ],
            "extra": ["Nenhuma acao e necessaria da sua parte."],
        },
        "on_hold": {
            "subject": [
                "Atualizacao sobre a vaga de {position}",
                "Novidades de contratacao na {company}",
            ],
            "intro": ["Ola {first},"],
            "core": [
                "Decidimos pausar a contratacao para a vaga de {position}.",
                "A vaga de {position} esta em espera ate a aprovacao orcamentaria.",
            ],
            "extra": ["Entraremos em contato quando a situacao mudar."],
        },
        "assessment": {
            "subject": ["Seus resultados da avaliacao", "Avaliacao concluida"],
            "intro": ["Ola {first},"],
            "core": [
                "Sua pontuacao foi de 62%; infelizmente voce nao atingiu o corte. Voce pode refazer o teste uma vez.",
                "Lamentamos que seu resultado tenha ficado abaixo do corte do processo para {position}.",
            ],
            "extra": ["Os resultados estao disponiveis no portal."],
        },
    },
    "adv": {
        "subject": [
            "Como esmagamos rejeicoes na JobHuntConf",
            "Sua candidatura foi rejeitada!",
            "Pagamento recusado",
            "A arte da carta de rejeicao",
        ],
        "intro": ["Ola {first},", "Oi {first},"],
        "core": [
            (
                "Sua candidatura foi rejeitada! - voce marcou 2 de 5 no Interview Quest e sua "
                "candidatura dentro do jogo foi rejeitada. Tenta de "
                "novo?",
                "other",
            ),
            (
                "Infelizmente nao podemos ultrapassar o bonus de assinatura - mas estamos felizes "
                "em oferecer a vaga de "
                "{position}!",
                "opportunity",
            ),
            (
                "Lamentamos informar que esta edicao e curta: a editora estava ocupada reunindo "
                "historias de rejeicao dos "
                "leitores.",
                "other",
            ),
            (
                "Infelizmente a vaga de {position} que voce salvou na {company} foi preenchida; "
                "veja cinco vagas "
                "parecidas.",
                "other",
            ),
            (
                "Sua entrevista para a vaga de {position} esta confirmada para terca as 14:00; "
                "lamentamos a falha anterior da "
                "ferramenta.",
                "opportunity",
            ),
        ],
        "extra": [
            "Responda SAIR para cancelar.",
            "Nada mudou sobre a sua candidatura real.",
            "Termos completos no nosso site.",
        ],
    },
}

BANKS["ru"] = {
    "names": [
        "Анна Смирнова",
        "Дмитрий Иванов",
        "Елена Кузнецова",
        "Сергей Попов",
        "Ольга Васильева",
        "Алексей Новиков",
        "Наталья Морозова",
        "Игорь Соколов",
    ],
    "companies": [
        "ТехНова",
        "Группа Север",
        "МедТех Альянс",
        "Финансовый Горизонт",
        "Логистика Юг",
        "Медиа Аврора",
        "Консалт Голубой",
        "Ритейл Путь",
    ],
    "positions": [
        "Старший Backend-инженер",
        "Аналитик данных",
        "Менеджер по маркетингу",
        "Медицинская сестра",
        "UX-дизайнер",
        "Менеджер по продажам",
        "Финансовый контролёр",
        "Руководитель проектов",
    ],
    "skills": ["Python", "логистика", "B2B-продажи", "финансовое моделирование"],
    "greet": ["Здравствуйте, {name}!", "Уважаемый(ая) {name}!", "Добрый день, {name}!"],
    "subject_rej": [
        "Обновление по вашей заявке",
        "Ваша заявка в {company}",
        "По поводу вакансии {position}",
        "Результат отбора",
    ],
    "decision": {
        "direct": [
            "Мы не будем продолжать работу с вашей заявкой.",
            "Рассмотрев ваши материалы, мы решили не продолжать.",
            "Вы не были выбраны на позицию {position}.",
            "Мы не переводим вас на следующий этап.",
        ],
        "polite": [
            "После тщательного рассмотрения мы с сожалением сообщаем, что не будем продолжать "
            "работу с вашей "
            "кандидатурой.",
            "Благодарим вас за время, потраченное на процесс, но мы решили продолжить с другим кандидатом.",
            "К сожалению, мы не сможем предложить вам позицию {position} в этот раз.",
            "Было приятно познакомиться с вашим опытом; к сожалению, мы вынуждены отклонить вашу заявку.",
        ],
        "brutal": [
            "Нет. Ваш опыт далеко не соответствует требованиям этой роли.",
            "Вы не подходите для этой работы. Пожалуйста, не подавайте заявку повторно.",
            "Мы отклонили вас, потому что портфолио слабое, а задание сдано с опозданием.",
            "Мы прочитали вашу заявку дважды, и оба раза ответ был нет.",
        ],
        "vague": [
            "Мы решили двигаться в другом направлении.",
            "После внутреннего рассмотрения мы не продолжаем работу с вашим профилем.",
            "Ваша заявка закрыта.",
            "Наши потребности изменились, и мы не будем продолжать работу с вашей заявкой.",
        ],
        "legal": [
            "Сообщаем вам, что {company} завершила рассмотрение вашей заявки и не будет делать предложения о работе.",
            "Настоящим письмом подтверждается, что ваша кандидатура на указанную должность "
            "завершена без дальнейших "
            "действий.",
            "Компания завершила проверку, предложение о работе сделано не будет; данное решение "
            "является "
            "окончательным.",
            "Ничто в данном сообщении не является трудовым договором или обязательством дальнейшего рассмотрения.",
        ],
        "agency": [
            "Наш клиент решил не продолжать работу с вашим профилем по контрактной роли.",
            "Менеджер по найму рассмотрел вашу заявку и, к сожалению, отказался.",
            "Мы направили вас в {company}, и ответ был отрицательным — они выбрали кандидата с "
            "большим опытом в "
            "{skill}.",
            "Плохие новости по вакансии {position}: клиент выбрал другого кандидата.",
        ],
        "internal": [
            "Хотел вас проинформировать: команда решила не продолжать с вами по позиции {position}.",
            "Только что получил ответ от менеджера по найму: они не продолжают работу с вашей заявкой.",
            "К сожалению, панель выбрала другого кандидата.",
            "Требования к роли изменились, и вы больше не в борьбе за {position}.",
        ],
        "ats": [
            "Ваша заявка на позицию {position} (ID {id}) не выбрана для дальнейшего рассмотрения.",
            "Обновление статуса: не выбран. Спасибо за интерес к {company}.",
            "Уважаемый кандидат, это автоматическое уведомление о закрытии вашей кандидатуры.",
            "Ваш профиль переведён в статус «Отклонён» в нашей системе отслеживания кандидатов.",
        ],
    },
    "context": [
        "Мы получили более 600 заявок на эту позицию.",
        "Отбор был очень конкурентным.",
        "Панель собралась в пятницу, чтобы рассмотреть оставшихся кандидатов.",
        "Поймите, это решение было принято не наспех.",
    ],
    "skill_line": [
        "Ваш опыт в {skill} не совсем соответствовал потребностям команды.",
        "Роль требовала более глубокого практического опыта в {skill}.",
    ],
    "thanks": [
        "Спасибо за время, которое вы уделили процессу.",
        "Благодарим за интерес к {company}.",
        "Спасибо за терпение в течение процесса.",
    ],
    "reopen": [
        "Мы сохраним ваше резюме для будущих вакансий.",
        "Вы можете подать заявку повторно, когда откроются новые позиции.",
        "Мы будем следить за возможностями, которые могут вам подойти.",
    ],
    "closing": ["С уважением,", "С наилучшими пожеланиями,", "Искренне ваш,", "Всего доброго,"],
    "titles": ["Рекрутер", "Специалист по подбору", "Менеджер по найму", "Координатор HR"],
    "neg": {
        "application_ack": {
            "subject": ["Мы получили вашу заявку", "Заявка получена - {position}"],
            "intro": ["Здравствуйте, {first}!", "Уважаемый кандидат!"],
            "core": [
                "Спасибо за заявку на позицию {position} в {company} — мы её получили.",
                "Ваша заявка на позицию {position} (ID {id}) получена и находится на рассмотрении.",
            ],
            "extra": [
                "Вы можете отслеживать статус в кандидатском портале.",
                "Этот ящик не обслуживается, пожалуйста, не отвечайте на письмо.",
            ],
        },
        "interview_invite": {
            "subject": [
                "Приглашение на собеседование - {position}",
                "Следующий шаг: давайте поговорим",
            ],
            "intro": ["Здравствуйте, {first}!", "{name}, добрый день!"],
            "core": [
                "Мы хотели бы пригласить вас на собеседование продолжительностью 45 минут на позицию {position}.",
                "Команде понравилась ваша заявка, и мы хотели бы перейти к следующему этапу.",
            ],
            "extra": [
                "Выберите удобное время по ссылке ниже.",
                "На собеседовании обсудим ваш опыт в {skill}.",
            ],
        },
        "offer_letter": {
            "subject": [
                "Предложение о работе - {company}",
                "Мы хотели бы предложить вам позицию {position}",
            ],
            "intro": ["{name}, добрый день!"],
            "core": [
                "Мы рады предложить вам должность {position} в {company}.",
                "После успешного финального этапа мы хотели бы пригласить вас в команду.",
            ],
            "extra": [
                "Детали вознаграждения приложены; подпишите до {date}.",
                "Дата выхода — {date}.",
            ],
        },
        "job_alert": {
            "subject": ["Новые вакансии для вас", "Рекомендуемые вакансии"],
            "intro": ["Здравствуйте, {first}!"],
            "core": [
                "На основе вашего профиля мы подобрали несколько новых вакансий.",
                "{company} нанимает на несколько позиций; посмотрите.",
            ],
            "extra": [
                "Чтобы отписаться, перейдите по ссылке ниже.",
                "Больше вакансий на нашем сайте.",
            ],
        },
        "recruiter_spam": {
            "subject": ["Давайте поговорим о возможностях", "Ваш профиль привлёк моё внимание"],
            "intro": ["Здравствуйте, {first}!", "Привет, {first}!"],
            "core": [
                "Я увидел ваш профиль и хотел бы обсудить возможности в области {skill}.",
                "Мы нанимаем на несколько позиций, и ваш опыт хорошо подходит.",
            ],
            "extra": [
                "Даже если время неудобное, давайте останемся на связи.",
                "Если удобно, пришлите резюме.",
            ],
        },
        "newsletter": {
            "subject": ["Карьерный вестник, выпуск 128", "Ваши карьерные советы на неделю"],
            "intro": ["Здравствуйте, {first}!"],
            "core": [
                "Добро пожаловать в еженедельный обзор Карьерного вестника.",
                "На этой неделе говорим о переговорах о релокационном пакете.",
            ],
            "extra": [
                "Перешлите это письмо тому, кто в активном поиске.",
                "Вы получаете это письмо, потому что подписаны на рассылку.",
            ],
        },
        "account_security": {
            "subject": [
                "Новый вход в ваш аккаунт",
                "Оповещение безопасности: необычная активность",
            ],
            "intro": ["Здравствуйте, {first}!"],
            "core": [
                "Мы зафиксировали новый вход в ваш аккаунт с нового устройства.",
                "Кто-то запросил сброс пароля вашего аккаунта.",
            ],
            "extra": [
                "Если это были не вы, немедленно защитите аккаунт.",
                "Никогда не передавайте коды подтверждения.",
            ],
        },
        "adversarial": {
            "subject": [
                "Ваша заявка отклонена!",
                "Платёж отклонён",
                "Re: ваше собеседование завтра",
            ],
            "intro": ["Здравствуйте, {first}!", "Привет, {first}!"],
            "core": [
                "Ваша заявка отклонена! — вы набрали 2 из 5 в Interview Quest, и ваша заявка "
                "внутри "
                "игры была отклонена. Попробуете ещё "
                "раз?",
                "К сожалению, мы не можем увеличить подписной бонус — но мы рады предложить вам позицию {position}!",
                "Ваш банк отклонил платёж. Обновите карту, чтобы сохранить Premium-подписку в {company}.",
                "К сожалению, вакансия {position}, которую вы сохранили в {company}, уже закрыта — "
                "вот пять похожих "
                "вакансий.",
            ],
            "extra": [
                "Ответьте СТОП, чтобы отписаться.",
                "Ничего не изменилось в вашей реальной заявке.",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["Давайте останемся на связи", "Ваш профиль в {company}"],
            "intro": ["Здравствуйте, {first}!"],
            "core": [
                "Ваш профиль нам понравился, и мы будем помнить о вас при будущих вакансиях.",
                "Давайте останемся на связи; у команды снова могут быть потребности в следующем квартале.",
            ],
            "extra": ["Пишите в любое время."],
        },
        "resume_on_file": {
            "subject": ["Ваша заявка в {company}", "Наша база талантов"],
            "intro": ["{name}, добрый день!"],
            "core": [
                "Ваше резюме добавлено в нашу базу талантов.",
                "Мы сохраним ваше резюме и свяжемся при появлении подходящей вакансии.",
            ],
            "extra": ["С вашей стороны никаких действий не требуется."],
        },
        "on_hold": {
            "subject": ["Обновление по вакансии {position}", "Новости найма в {company}"],
            "intro": ["Здравствуйте, {first}!"],
            "core": [
                "Мы решили приостановить найм на позицию {position}.",
                "Вакансия {position} приостановлена до утверждения бюджета.",
            ],
            "extra": ["Мы свяжемся с вами, когда ситуация изменится."],
        },
        "assessment": {
            "subject": ["Результаты вашей оценки", "Оценка завершена"],
            "intro": ["Здравствуйте, {first}!"],
            "core": [
                "Ваш результат — 62%; к сожалению, вы не достигли порога. Вы можете пройти тест ещё раз.",
                "К сожалению, ваш результат оказался ниже порога процесса по {position}.",
            ],
            "extra": ["Результаты доступны в портале кандидата."],
        },
    },
    "adv": {
        "subject": [
            "Как мы крушили отказы на JobHuntConf",
            "Ваша заявка отклонена!",
            "Платёж отклонён",
            "Искусство письма об отказе",
        ],
        "intro": ["Здравствуйте, {first}!", "Привет, {first}!"],
        "core": [
            (
                "Ваша заявка отклонена! — вы набрали 2 из 5 в Interview Quest, и ваша заявка "
                "внутри "
                "игры была отклонена. Попробуете ещё "
                "раз?",
                "other",
            ),
            (
                "К сожалению, мы не можем увеличить подписной бонус — но мы рады предложить вам позицию {position}!",
                "opportunity",
            ),
            (
                "К сожалению, выпуск короткий: редактор собирала истории отказов наших читателей.",
                "other",
            ),
            (
                "К сожалению, вакансия {position}, которую вы сохранили в {company}, уже закрыта — "
                "вот пять похожих "
                "вакансий.",
                "other",
            ),
            (
                "Ваше собеседование на позицию {position} подтверждено на вторник, 14:00; приносим "
                "извинения за сбой "
                "планировщика.",
                "opportunity",
            ),
        ],
        "extra": [
            "Ответьте СТОП, чтобы отписаться.",
            "Ничего не изменилось в вашей реальной заявке.",
            "Полные условия на нашем сайте.",
        ],
    },
}

BANKS["ja"] = {
    "names": [
        "田中 美咲",
        "佐藤 健太",
        "鈴木 陽子",
        "高橋 大輔",
        "伊藤 さくら",
        "渡辺 拓也",
        "山本 直子",
        "中村 翔",
    ],
    "companies": [
        "テックノヴァ株式会社",
        "青空データ",
        "ヘルスケア地平線",
        "南風ロジスティクス",
        "金橋ファイナンス",
        "みらい教育",
        "星原メディア",
        "クラウド技研",
    ],
    "positions": [
        "シニアバックエンドエンジニア",
        "データアナリスト",
        "マーケティングマネージャー",
        "看護師",
        "UXデザイナー",
        "営業担当",
        "財務コントローラー",
        "プロジェクトマネージャー",
    ],
    "skills": ["Python", "サプライチェーン", "B2B営業", "データ分析"],
    "greet": ["{name} 様", "{name} さん", "{name} 様 こんにちは"],
    "subject_rej": [
        "ご応募の結果について",
        "{company} でのご応募状況",
        "{position} 職のご応募結果",
        "採用選考のご連絡",
    ],
    "decision": {
        "direct": [
            "今回は、ご応募を前進させることはいたしません。",
            "書類を拝見した結果、選考を進めない決定をいたしました。",
            "{position} 職では、選考対象となりませんでした。",
            "次のステップへのご案内はいたしかねます。",
        ],
        "polite": [
            "慎重に検討した結果、誠に残念ながら今回はご応募を進められないこととなりました。",
            "選考にお時間をいただきありがとうございます。他候補者と進めていく決定をいたしました。",
            "誠に申し訳ございませんが、今回は {position} 職をご提案できかねます。",
            "お話できて光栄でした。誠に残念ですが、ご応募をお断りする運びとなりました。",
        ],
        "brutal": [
            "いいえ。この職務に必要な経験には程遠いです。",
            "この仕事の要件を満たしていません。再応募はお控えください。",
            "ポートフォリオが弱く課題の提出も遅れたため、お断りしました。",
            "応募書類を2回読みましたが、どちらも答えは「いいえ」でした。",
        ],
        "vague": [
            "別の方向に進むことにしました。",
            "社内で検討した結果、選考は進めません。",
            "ご応募はクローズいたしました。",
            "当社の要件が変わり、選考を継続できません。",
        ],
        "legal": [
            "ここに通知いたします。{company} は貴殿の応募の検討を終了し、雇用のオファーは行いません。",
            "本書をもって、上記職位への貴殿の立候補はこれ以上の手続きなく終了したことを確認します。",
            "当社は審査を完了し、雇用のオファーは行いません。本決定は最終です。",
            "本通信のいかなる部分も雇用契約や将来の検討の約束を構成するものではありません。",
        ],
        "agency": [
            "クライアントは契約職について、貴殿のプロフィールを進めない決定をしました。",
            "採用責任者がご応募を確認しましたが、残念ながら見送りとなりました。",
            "{company} に推薦しましたが、回答は残念ながら不採用でした。{skill} の経験がより豊富な方を選びました。",
            "{position} 職から悪い知らせです。クライアントは別の候補者を選びました。",
        ],
        "internal": [
            "ご連絡したく存じます。チームは {position} 職について、選考を進めない決定をしました。",
            "採用マネージャーから先ほど回答があり、ご応募は進めないとのことでした。",
            "残念ながら、面接パネルは別の候補者を選びました。",
            "職務内容が見直され、{position} の選考には残っていません。",
        ],
        "ats": [
            "{position} 職（ID {id}）へのご応募は、次の選考には進みませんでした。",
            "ステータス更新：不採用。{company} へのご関心をお礼申し上げます。",
            "応募者各位、これは自動通知です。貴殿の選考はクローズされました。",
            "貴殿のプロフィールは当社の採用管理システムで「不採用」に変更されました。",
        ],
    },
    "context": [
        "この職務には600件を超えるご応募をいただきました。",
        "非常に競争率の高い選考でした。",
        "面接パネルは金曜日に残りの候補者を検討しました。",
        "この決定は軽率なものではございませんでした。",
    ],
    "skill_line": [
        "{skill} におけるご経験は、チームの求めるものと少し異なりました。",
        "この職務では {skill} の実務経験がより重視されていました。",
    ],
    "thanks": [
        "選考にお時間をいただき、ありがとうございました。",
        "{company} へのご関心に感謝申し上げます。",
        "選考期間中のご忍耐に感謝いたします。",
    ],
    "reopen": [
        "今後の求人のために、履歴書を保管いたします。",
        "新しいポジションが公開された際は、再応募いただけます。",
        "貴殿に合う機会があればお知らせします。",
    ],
    "closing": [
        "敬具",
        "よろしくお願いいたします",
        "何卒よろしくお願い申し上げます",
        "まずはご連絡まで",
    ],
    "titles": ["採用担当", "タレントアキュイジション", "採用マネージャー", "人事コーディネーター"],
    "neg": {
        "application_ack": {
            "subject": ["ご応募を受け付けました", "応募受付のお知らせ - {position}"],
            "intro": ["{name} 様", "{name} さん"],
            "core": [
                "{company} の {position} 職にご応募いただきありがとうございます。ご応募を受け付けました。",
                "{position} 職（ID {id}）へのご応募を受け付け、現在審査中です。",
            ],
            "extra": [
                "候補者ポータルでいつでも状況をご確認いただけます。",
                "このメールボックスは自動受信です。ご返信はご遠慮ください。",
            ],
        },
        "interview_invite": {
            "subject": ["面接のご案内 - {position}", "次のステップ：お話ししましょう"],
            "intro": ["{name} 様", "{name} さん"],
            "core": [
                "{position} 職について、45分の面接にご招待したいと考えております。",
                "チームはご応募を評価しており、次のステップに進めたいと考えています。",
            ],
            "extra": [
                "下記リンクからご都合の良い日時をお選びください。",
                "面接では {skill} に関するご経験についてお伺いします。",
            ],
        },
        "offer_letter": {
            "subject": ["採用のご内定 - {company}", "{position} 職のごオファー"],
            "intro": ["{name} 様"],
            "core": [
                "{company} の {position} 職への採用をご案内でき、光栄です。",
                "最終面接の結果、ぜひチームにご参加いただきたいと考えております。",
            ],
            "extra": [
                "報酬条件は添付の通りです。{date} までにご署名ください。",
                "入社日は {date} です。",
            ],
        },
        "job_alert": {
            "subject": ["あなたにおすすめの求人", "新しい求人のお知らせ"],
            "intro": ["{name} さん"],
            "core": [
                "プロフィールをもとに、いくつかの新しい求人をご案内します。",
                "{company} では複数の職種で採用中です。ご確認ください。",
            ],
            "extra": [
                "配信停止は下記リンクから手続きできます。",
                "その他の求人は当社サイトをご覧ください。",
            ],
        },
        "recruiter_spam": {
            "subject": ["新しい機会についてご連絡しました", "プロフィールを拝見しました"],
            "intro": ["{name} さん", "こんにちは {name} さん"],
            "core": [
                "プロフィールを拝見し、{skill} 分野の機会についてご連絡しました。",
                "複数の職種で採用しており、ご経験に合うかと思いました。",
            ],
            "extra": [
                "タイミングが合わなくても、ご連絡いただければ幸いです。",
                "よろしければ履歴書をお送りください。",
            ],
        },
        "newsletter": {
            "subject": ["キャリア週報 第128号", "今週のキャリアアドバイス"],
            "intro": ["{name} さん"],
            "core": [
                "キャリア週報へようこそ。",
                "今週号では、異動パッケージの交渉について取り上げます。",
            ],
            "extra": [
                "転職活動中の方にお送りください。",
                "このメールはご登録いただいているためお届けしています。",
            ],
        },
        "account_security": {
            "subject": ["アカウントへの新しいサインイン", "セキュリティ警告：不審なアクティビティ"],
            "intro": ["{name} さん"],
            "core": [
                "新しいデバイスからのアカウントへのサインインを検知しました。",
                "アカウントのパスワードリセットがリクエストされました。",
            ],
            "extra": [
                "心当たりがない場合は、直ちにアカウントを保護してください。",
                "確認コードを誰にも共有しないでください。",
            ],
        },
        "adversarial": {
            "subject": [
                "あなたの応募は却下されました！",
                "お支払いが拒否されました",
                "Re: 明日の面接について",
            ],
            "intro": ["{name} さん", "こんにちは {name} さん"],
            "core": [
                "あなたの応募は却下されました！ - Interview Quest で"
                "5点満点中2点を獲得し、ゲーム内の応募が却下されました。再挑戦しますか？",
                "申し訳ございませんが、サインインボーナスは5千ドルを超えることはできません"
                " - ただし、{position} 職をご提案できることを嬉しく思います！",
                "お支払いが銀行により拒否されました。{company} の"
                "プレミアム会員を維持するにはカード情報を更新してください。",
                "申し訳ございませんが、{company} で保存された {posi"
                "tion} 職はすでに埋まりました。類似の求人を5件ご案内します。",
            ],
            "extra": ["停止と返信すると配信停止できます。", "実際の応募状況に変化はありません。"],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["ご連絡を続けましょう", "{company} でのプロフィール"],
            "intro": ["{name} さん"],
            "core": [
                "プロフィールは興味深く拝見し、今後の求人の際に覚えておきます。",
                "ご連絡を続けましょう。来四半期にチームの求人が出るかもしれません。",
            ],
            "extra": ["いつでもご連絡ください。"],
        },
        "resume_on_file": {
            "subject": ["{company} でのご応募", "人材データベース"],
            "intro": ["{name} 様"],
            "core": [
                "履歴書を人材データベースに登録しました。",
                "履歴書を保管し、適したポジションがあればご連絡します。",
            ],
            "extra": ["貴殿側で必要な手続きはありません。"],
        },
        "on_hold": {
            "subject": ["{position} 職についてのご連絡", "{company} 採用状況のお知らせ"],
            "intro": ["{name} さん"],
            "core": [
                "{position} 職の採用を一時停止することにしました。",
                "この職務は予算承認待ちで保留中です。",
            ],
            "extra": ["状況が変わりましたらご連絡します。"],
        },
        "assessment": {
            "subject": ["適性検査の結果", "検査が完了しました"],
            "intro": ["{name} 様"],
            "core": [
                "検査のスコアは62%でした。申し訳ございませんが、基準に達しませんでした。一度だけ再受験できます。",
                "残念ながら、結果は {position} 選考の基準を下回りました。",
            ],
            "extra": ["結果は候補者ポータルでご確認いただけます。"],
        },
    },
    "adv": {
        "subject": [
            "JobHuntConf で却下に打ち勝った方法",
            "あなたの応募は却下されました！",
            "お支払いが拒否されました",
            "お断りメールの芸術",
        ],
        "intro": ["{name} さん", "こんにちは {name} さん"],
        "core": [
            (
                "あなたの応募は却下されました！ - Interview Quest で"
                "5点満点中2点を獲得し、ゲーム内の応募が却下されました。再挑戦しますか？",
                "other",
            ),
            (
                "申し訳ございませんが、サインインボーナスは5千ドルを超えることはできません"
                " - ただし、{position} 職をご提案できることを嬉しく思います！",
                "opportunity",
            ),
            (
                "申し訳ございませんが、今号は短くなっています。編集者が読者からのお断りエピソードの収集に追われていました。",
                "other",
            ),
            (
                "申し訳ございませんが、{company} で保存された {posi"
                "tion} 職はすでに埋まりました。類似の求人を5件ご案内します。",
                "other",
            ),
            (
                "{position} 職の面接は火曜日14:00に確定しました。先ほどのスケジュールツールの不具合を詫びます。",
                "opportunity",
            ),
        ],
        "extra": [
            "停止と返信すると配信停止できます。",
            "実際の応募状況に変化はありません。",
            "詳細な条件は当社サイトをご覧ください。",
        ],
    },
}

BANKS["de"] = {
    "names": [
        "Lena Hoffmann",
        "Markus Weber",
        "Sara Yilmaz",
        "Jonas Becker",
        "Anna Schulz",
        "David Fischer",
        "Miriam Klein",
        "Thomas Wagner",
    ],
    "companies": [
        "Innotech Deutschland",
        "Nordwind Logistik",
        "Helios Gesundheit",
        "Cobalt Finanzen",
        "Redwood Medien",
        "Bluepeak Consulting",
        "Meridian Handel",
        "Vantage Cloud",
    ],
    "positions": [
        "Senior Backend Engineer",
        "Datenanalystin",
        "Marketing Manager",
        "Pflegefachkraft",
        "UX Designerin",
        "Account Executive",
        "Finanzcontroller",
        "Projektmanager",
    ],
    "skills": ["Python", "Supply Chain", "B2B-Vertrieb", "Finanzmodellierung"],
    "greet": ["Hallo {name},", "Sehr geehrte/r {name},", "Guten Tag {name},"],
    "subject_rej": [
        "Rueckmeldung zu Ihrer Bewerbung",
        "Ihre Bewerbung bei {company}",
        "Betreffend die Position {position}",
        "Ergebnis des Bewerbungsprozesses",
    ],
    "decision": {
        "direct": [
            "Wir werden Ihre Bewerbung nicht weiter verfolgen.",
            "Nach Pruefung Ihrer Unterlagen haben wir uns entschieden, nicht weiterzugehen.",
            "Sie wurden fuer die Position {position} nicht ausgewaehlt.",
            "Wir laden Sie nicht zur naechsten Runde ein.",
        ],
        "polite": [
            "Nach sorgfaeltiger Ueberlegung muessen wir Ihnen leider mitteilen, dass wir Ihre "
            "Bewerbung nicht weiter "
            "verfolgen.",
            "Wir danken fuer die Zeit, die Sie in den Prozess investiert haben, haben uns aber "
            "fuer "
            "einen anderen Kandidaten "
            "entschieden.",
            "Leider koennen wir Ihnen die Position {position} diesmal nicht anbieten.",
            "Es war eine Freude, mit Ihnen zu sprechen; leider muessen wir Ihre Bewerbung ablehnen.",
        ],
        "brutal": [
            "Nein. Ihre Erfahrung kommt nicht annaehernd an das heran, was diese Rolle erfordert.",
            "Sie sind fuer diese Stelle nicht qualifiziert. Bitte bewerben Sie sich nicht erneut.",
            "Wir haben Sie abgelehnt, weil Ihr Portfolio schwach war und die Aufgabe spaet kam.",
            "Wir haben Ihre Bewerbung zweimal gelesen und beide Male war die Antwort nein.",
        ],
        "vague": [
            "Wir haben uns entschieden, eine andere Richtung einzuschlagen.",
            "Nach interner Pruefung verfolgen wir Ihr Profil nicht weiter.",
            "Ihre Bewerbung wurde geschlossen.",
            "Unsere Anforderungen haben sich geaendert; wir setzen Ihre Bewerbung nicht fort.",
        ],
        "legal": [
            "Hiermit teilen wir Ihnen mit, dass {company} die Pruefung Ihrer Bewerbung "
            "abgeschlossen hat und kein Arbeitsangebot unterbreiten "
            "wird.",
            "Dieses Schreiben bestaetigt, dass Ihre Kandidatur fuer die genannte Position ohne "
            "weitere Massnahmen abgeschlossen "
            "ist.",
            "Die Gesellschaft hat ihre Pruefung abgeschlossen; es wird kein Arbeitsangebot "
            "unterbreitet. Diese Entscheidung ist "
            "endgueltig.",
            "Nichts in dieser Mitteilung stellt einen Arbeitsvertrag oder eine Zusage kuenftiger Pruefung dar.",
        ],
        "agency": [
            "Unser Kunde hat entschieden, Ihr Profil fuer die Vertragsstelle nicht weiterzuverfolgen.",
            "Der Hiring Manager hat Ihre Unterlagen geprueft und leider abgelehnt.",
            "Wir haben Sie bei {company} vorgestellt; die Rueckmeldung war negativ - sie wählten "
            "jemanden mit mehr Erfahrung in "
            "{skill}.",
            "Schlechte Nachrichten zur Position {position}: der Kunde hat einen anderen Kandidaten gewaehlt.",
        ],
        "internal": [
            "Ich wollte Sie informieren: das Team hat entschieden, Sie fuer {position} nicht weiterzuberuecksichtigen.",
            "Ich habe gerade Rueckmeldung vom Hiring Manager: sie verfolgen Ihre Bewerbung nicht weiter.",
            "Es tut mir leid, das Panel hat einen anderen Kandidaten gewaehlt.",
            "Die Anforderungen wurden neu definiert; Sie sind fuer {position} nicht mehr im Rennen.",
        ],
        "ats": [
            "Ihre Bewerbung auf die Position {position} (ID {id}) wurde nicht fuer die naechste Runde ausgewaehlt.",
            "Statusupdate: Nicht ausgewaehlt. Vielen Dank fuer Ihr Interesse an {company}.",
            "Sehr geehrte Bewerberin, sehr geehrter Bewerber, dies ist eine automatische "
            "Benachrichtigung: Ihre Kandidatur wurde "
            "geschlossen.",
            "Ihr Profil wurde in unserem Bewerbermanagement-System auf den Status Abgelehnt gesetzt.",
        ],
    },
    "context": [
        "Wir haben ueber 600 Bewerbungen fuer diese Stelle erhalten.",
        "Es war ein sehr wettbewerbsintensiver Prozess.",
        "Das Panel hat am Freitag die verbleibenden Kandidaten geprueft.",
        "Bitte wissen Sie, dass diese Entscheidung nicht leichtfertig getroffen wurde.",
    ],
    "skill_line": [
        "Ihr Hintergrund in {skill} entsprach nicht ganz dem, was das Team brauchte.",
        "Die Rolle erforderte mehr praktische Erfahrung in {skill}.",
    ],
    "thanks": [
        "Vielen Dank fuer die Zeit, die Sie in den Prozess gesteckt haben.",
        "Wir danken fuer Ihr Interesse an {company}.",
        "Danke fuer Ihre Geduld waehrend des Prozesses.",
    ],
    "reopen": [
        "Wir bewahren Ihre Unterlagen fuer zukuenftige Stellen auf.",
        "Sie koennen sich erneut bewerben, wenn neue Stellen offen sind.",
        "Wir achten auf passende Gelegenheiten fuer Sie.",
    ],
    "closing": ["Mit freundlichen Gruessen", "Herzliche Gruesse", "Beste Gruesse", "Viele Gruesse"],
    "titles": ["Recruiterin", "Talent Acquisition", "Hiring Manager", "HR-Koordination"],
    "neg": {
        "application_ack": {
            "subject": ["Wir haben Ihre Bewerbung erhalten", "Bewerbung eingegangen - {position}"],
            "intro": ["Hallo {first},", "Sehr geehrte/r {first},"],
            "core": [
                "Vielen Dank fuer Ihre Bewerbung auf die Position {position} bei {company} - wir haben sie erhalten.",
                "Ihre Bewerbung auf die Position {position} (ID {id}) ist eingegangen und wird geprueft.",
            ],
            "extra": [
                "Den Status koennen Sie jederzeit im Bewerberportal einsehen.",
                "Dieses Postfach wird nicht gelesen; bitte antworten Sie nicht auf diese E-Mail.",
            ],
        },
        "interview_invite": {
            "subject": [
                "Einladung zum Interview - {position}",
                "Naechster Schritt: lass uns sprechen",
            ],
            "intro": ["Hallo {first},", "Hallo {name},"],
            "core": [
                "Wir moechten Sie zu einem 45-minuetigen Interview fuer die Position {position} einladen.",
                "Das Team hat Ihre Bewerbung positiv bewertet und moechte in die naechste Runde gehen.",
            ],
            "extra": [
                "Waehlen Sie ueber den Link unten einen Termin.",
                "Im Interview sprechen wir ueber Ihre Erfahrung in {skill}.",
            ],
        },
        "offer_letter": {
            "subject": [
                "Angebot - {company}",
                "Wir moechten Ihnen die Position {position} anbieten",
            ],
            "intro": ["Hallo {name},"],
            "core": [
                "Wir freuen uns, Ihnen die Position {position} bei {company} anbieten zu koennen.",
                "Nach der erfolgreichen Finalrunde moechten wir Sie ins Team holen.",
            ],
            "extra": [
                "Die Verguetungsdetails sind angehaengt; bitte unterschreiben Sie bis {date}.",
                "Ihr Startdatum ist der {date}.",
            ],
        },
        "job_alert": {
            "subject": ["Neue Jobs fuer Sie", "Empfohlene Stellenangebote"],
            "intro": ["Hallo {first},"],
            "core": [
                "Basierend auf Ihrem Profil haben wir einige neue Stellen zusammengestellt.",
                "{company} stellt fuer mehrere Positionen ein; schauen Sie vorbei.",
            ],
            "extra": [
                "Zum Abmelden klicken Sie auf den Link unten.",
                "Weitere Jobs finden Sie auf unserer Website.",
            ],
        },
        "recruiter_spam": {
            "subject": [
                "Kurze Frage zu Ihrem Profil",
                "Ihr Profil hat meine Aufmerksamkeit erregt",
            ],
            "intro": ["Hallo {first},", "Hey {first},"],
            "core": [
                "Ich bin ueber Ihr Profil gestossen und moechte Ihnen Rollen im Bereich {skill} vorstellen.",
                "Wir stellen mehrere Positionen ein und Ihre Erfahrung passt gut.",
            ],
            "extra": [
                "Auch wenn der Zeitpunkt nicht passt, bleiben wir gerne in Kontakt.",
                "Senden Sie mir gern Ihren Lebenslauf.",
            ],
        },
        "newsletter": {
            "subject": ["Der Karriere-Wochenbrief, Ausgabe 128", "Ihre Karrieretipps der Woche"],
            "intro": ["Hallo {first},"],
            "core": [
                "Willkommen zu Ihrem Wochenrundbrief vom Karriere-Wochenbrief.",
                "Diese Woche: wie man ein Relokationspaket verhandelt.",
            ],
            "extra": [
                "Leiten Sie diese Ausgabe an Jobsuchende weiter.",
                "Sie erhalten diese Mail, weil Sie abonniert haben.",
            ],
        },
        "account_security": {
            "subject": [
                "Neue Anmeldung bei Ihrem Konto",
                "Sicherheitswarnung: ungewoehnliche Aktivitaet",
            ],
            "intro": ["Hallo {first},"],
            "core": [
                "Wir haben eine neue Anmeldung bei Ihrem Konto von einem neuen Geraet festgestellt.",
                "Jemand hat ein Zuruecksetzen Ihres Passworts angefordert.",
            ],
            "extra": [
                "Falls Sie das nicht waren, sichern Sie Ihr Konto sofort.",
                "Geben Sie Ihre Bestaetigungscodes niemals weiter.",
            ],
        },
        "adversarial": {
            "subject": [
                "Ihre Bewerbung wurde abgelehnt!",
                "Zahlung abgelehnt",
                "Re: Ihr Interview morgen",
            ],
            "intro": ["Hallo {first},", "Hey {first},"],
            "core": [
                "Ihre Bewerbung wurde abgelehnt! - Sie haben bei Interview Quest 2 von 5 Punkten "
                "erreicht und Ihre Bewerbung im Spiel wurde abgelehnt. Nochmal "
                "versuchen?",
                "Leider koennen wir das Signing Bonus nicht ueber 5.000 Euro anheben - aber wir "
                "freuen uns, Ihnen die Position {position} "
                "anzubieten!",
                "Ihre Bank hat die Zahlung abgelehnt. Aktualisieren Sie Ihre Karte, um Ihr "
                "{company} Premium-Abo zu "
                "behalten.",
                "Leider ist die gespeicherte Position {position} bei {company} bereits besetzt - "
                "hier sind fuenf aehnliche "
                "Stellen.",
            ],
            "extra": [
                "Antworten Sie mit STOP, um diese Tipps abzubestellen.",
                "An Ihrem echten Bewerbungsstatus hat sich nichts geaendert.",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["Bleiben wir in Kontakt", "Ihr Profil bei {company}"],
            "intro": ["Hallo {first},", "Hallo {name},"],
            "core": [
                "Ihr Profil hat uns interessiert; wir merken uns Sie fuer zukuenftige Stellen.",
                "Bleiben wir in Kontakt; das Team koennte im naechsten Quartal wieder Bedarf haben.",
            ],
            "extra": ["Melden Sie sich jederzeit gern."],
        },
        "resume_on_file": {
            "subject": ["Ihre Bewerbung bei {company}", "Unser Talentpool"],
            "intro": ["Hallo {name},"],
            "core": [
                "Ihr Lebenslauf wurde unserem Talentpool hinzugefuegt.",
                "Wir bewahren Ihre Unterlagen auf und melden uns, wenn eine passende Stelle offen ist.",
            ],
            "extra": ["Sie muessen nichts weiter unternehmen."],
        },
        "on_hold": {
            "subject": ["Update zur Position {position}", "Recruiting-News von {company}"],
            "intro": ["Hallo {first},"],
            "core": [
                "Wir haben entschieden, die Einstellung fuer {position} zu pausieren.",
                "Die Position {position} steht bis zur Budgetfreigabe auf Hold.",
            ],
            "extra": ["Wir melden uns, sobald sich die Lage aendert."],
        },
        "assessment": {
            "subject": ["Ihre Assessment-Ergebnisse", "Assessment abgeschlossen"],
            "intro": ["Hallo {first},"],
            "core": [
                "Ihre Punktzahl lag bei 62 %; leider haben Sie die Schwelle nicht erreicht. Sie "
                "koennen den Test einmal "
                "wiederholen.",
                "Leider lag Ihr Ergebnis unter der Schwelle des Prozesses fuer {position}.",
            ],
            "extra": ["Die Ergebnisse finden Sie im Bewerberportal."],
        },
    },
    "adv": {
        "subject": [
            "Wie wir Ablehnungen bei JobHuntConf zermalmt haben",
            "Ihre Bewerbung wurde abgelehnt!",
            "Zahlung abgelehnt",
            "Die Kunst des Ablehnungsschreibens",
        ],
        "intro": ["Hallo {first},", "Hey {first},"],
        "core": [
            (
                "Ihre Bewerbung wurde abgelehnt! - Sie haben bei Interview Quest 2 von 5 Punkten "
                "erreicht und Ihre Bewerbung im Spiel wurde abgelehnt. Nochmal "
                "versuchen?",
                "other",
            ),
            (
                "Leider koennen wir das Signing Bonus nicht anheben - aber wir freuen uns, Ihnen "
                "die Position {position} "
                "anzubieten!",
                "opportunity",
            ),
            (
                "Leider ist diese Ausgabe kurz: die Redaktion war mit dem Einsammeln von "
                "Ablehnungsgeschichten unserer Leser "
                "beschaeftigt.",
                "other",
            ),
            (
                "Leider ist die gespeicherte Position {position} bei {company} bereits besetzt - "
                "hier sind fuenf aehnliche "
                "Stellen.",
                "other",
            ),
            (
                "Ihr Interview fuer die Position {position} ist fuer Dienstag 14:00 Uhr "
                "bestaetigt; "
                "wir entschaeldigen uns fuer die Stoerung des "
                "Planungstools.",
                "opportunity",
            ),
        ],
        "extra": [
            "Antworten Sie mit STOP zum Abbestellen.",
            "An Ihrem echten Bewerbungsstatus hat sich nichts geaendert.",
            "Vollstaendige Bedingungen auf unserer Website.",
        ],
    },
}

BANKS["el"] = {
    "names": [
        "Γιώργος Παπαδόπουλος",
        "Ελένη Νικολάου",
        "Νίκος Αλεξίου",
        "Μαρία Κωνσταντίνου",
        "Δημήτρης Παπαγεωργίου",
        "Αννα Βασιλείου",
        "Κώστας Μιχαηλίδης",
        "Σοφία Θεοδώρου",
    ],
    "companies": [
        "ΤεκΝόβα",
        "Όμιλος Βορράς",
        "Υγεία Ορίζοντας",
        "Χρηματοοικονομική Αυγή",
        "Νότια Λογιστική",
        "Μέσα Αυγή",
        "Σύμβουλοι Γαλάζιο",
        "Λιανική Δρόμος",
    ],
    "positions": [
        "Senior Backend Engineer",
        "Αναλυτής Δεδομένων",
        "Υπεύθυνος Μάρκετινγκ",
        "Νοσηλεύτρια",
        "UX Designer",
        "Υπεύθυνος Πωλήσεων",
        "Χρηματοοικονομικός Controller",
        "Διαχειριστής Έργων",
    ],
    "skills": ["Python", "εφοδιαστική αλυσίδα", "B2B πωλήσεις", "χρηματοοικονομική μοντελοποίηση"],
    "greet": ["Γεια σας {name},", "Αγαπητέ/η {name},", "Καλημέρα {name},"],
    "subject_rej": [
        "Ενημέρωση για την αίτησή σας",
        "Η αίτησή σας στην {company}",
        "Σχετικά με τη θέση {position}",
        "Αποτέλεσμα διαδικασίας επιλογής",
    ],
    "decision": {
        "direct": [
            "Δεν θα προχωρήσουμε στην αίτησή σας.",
            "Μετά την αξιολόγηση των υλικών σας, αποφασίσαμε να μην προχωρήσουμε.",
            "Δεν επιλεχθήκατε για τη θέση {position}.",
            "Δεν σας προχωρούμε στο επόμενο στάδιο.",
        ],
        "polite": [
            "Μετά από προσεκτική εξέταση, λυπούμαστε να σας ενημερώσουμε ότι δεν θα προχωρήσουμε "
            "στην υποψηφιότητά "
            "σας.",
            "Σας ευχαριστούμε για τον χρόνο που διαθέσατε, αλλά αποφασίσαμε να προχωρήσουμε με άλλον υποψήφιο.",
            "Δυστυχώς δεν μπορούμε να σας προσφέρουμε τη θέση {position} αυτή τη φορά.",
            "Ήταν ευχάριστο να γνωρίσουμε το υπόβαθρό σας· δυστυχώς πρέπει να απορρίψουμε την αίτησή σας.",
        ],
        "brutal": [
            "Όχι. Η εμπειρία σας είναι πολύ μακριά από ό,τι απαιτεί αυτός ο ρόλος.",
            "Δεν είστε κατάλληλος/η για αυτή τη δουλειά. Παρακαλώ μην ξανακάνετε αίτηση.",
            "Σας απορρίψαμε επειδή το portfolio σας ήταν αδύναμο και η εργασία ήρθε αργά.",
            "Διαβάσαμε την αίτησή σας δύο φορές και και οι δύο φορές η απάντηση ήταν όχι.",
        ],
        "vague": [
            "Αποφασίσαμε να πάμε προς μια άλλη κατεύθυνση.",
            "Μετά από εσωτερική εξέταση, δεν προχωρούμε με το προφίλ σας.",
            "Η αίτησή σας έκλεισε.",
            "Οι ανάγκες μας άλλαξαν και δεν συνεχίζουμε την αίτησή σας.",
        ],
        "legal": [
            "Σας ενημερώνουμε ότι η {company} ολοκλήρωσε την εξέταση της αίτησής σας και δεν θα "
            "κάνει προσφορά "
            "εργασίας.",
            "Το παρόν επιστολικό έγγραφο επιβεβαιώνει ότι η υποψηφιότητά σας για την αναφερόμενη "
            "θέση έχει ολοκληρωθεί χωρίς περαιτέρω "
            "ενέργειες.",
            "Η Εταιρεία ολοκλήρωσε τον έλεγχό της και δεν θα γίνει προσφορά εργασίας· η απόφαση είναι τελική.",
            "Τίποτα στην παρούσα επικοινωνία δεν αποτελεί σύμβαση εργασίας ή δέσμευση μελλοντικής εξέτασης.",
        ],
        "agency": [
            "Ο πελάτης μας αποφάσισε να μην προχωρήσει με το προφίλ σας για τη συμβατική θέση.",
            "Ο υπεύθυνος πρόσληψης εξέτασε την αίτησή σας και δυστυχώς δεν προχώρησε.",
            "Σας προτείναμε στην {company} και η απάντηση ήταν αρνητική· επέλεξαν κάποιον με "
            "περισσότερη εμπειρία στο "
            "{skill}.",
            "Κακά νέα για τη θέση {position}: ο πελάτης επέλεξε άλλον υποψήφιο.",
        ],
        "internal": [
            "Θέλησα να σας ενημερώσω· η ομάδα αποφάσισε να μην προχωρήσει μαζί σας για τη θέση {position}.",
            "Μόλις ήρθε απάντηση από τον υπεύθυνο πρόσληψης· δεν προχωρούν στην αίτησή σας.",
            "Λυπάμαι να το πω· η επιτροπή επέλεξε άλλον υποψήφιο.",
            "Οι απαιτήσεις της θέσης άλλαξαν και δεν είστε πια στον διαγωνισμό για το {position}.",
        ],
        "ats": [
            "Η αίτησή σας για τη θέση {position} (ID {id}) δεν επιλέχθηκε για περαιτέρω εξέταση.",
            "Ενημέρωση κατάστασης: Μη επιλεγμένος/η. Ευχαριστούμε για το ενδιαφέρον σας στην {company}.",
            "Αγαπητέ υποψήφιε, αυτή είναι αυτόματη ειδοποίηση ότι η υποψηφιότητά σας έκλεισε.",
            "Το προφίλ σας μεταφέρθηκε στην κατάσταση Απορρίφθηκε στο σύστημα παρακολούθησης υποψηφίων.",
        ],
    },
    "context": [
        "Λάβαμε πάνω από 600 αιτήσεις για αυτή τη θέση.",
        "Ήταν μια πολύ ανταγωνιστική διαδικασία.",
        "Η επιτροπή συνήλθε την Παρασκευή για να εξετάσει τους υπολειπόμενους υποψηφίους.",
        "Να γνωρίζετε ότι η απόφαση δεν ελήφθη πρόχειρα.",
    ],
    "skill_line": [
        "Το υπόβαθρό σας στο {skill} δεν ήταν ακριβώς αυτό που χρειαζόταν η ομάδα.",
        "Ο ρόλος απαιτούσε περισσότερη πρακτική εμπειρία στο {skill}.",
    ],
    "thanks": [
        "Ευχαριστούμε για τον χρόνο που διαθέσατε στη διαδικασία.",
        "Εκτιμούμε το ενδιαφέρον σας για την {company}.",
        "Ευχαριστούμε για την υπομονή σας.",
    ],
    "reopen": [
        "Θα κρατήσουμε το βιογραφικό σας για μελλοντικές θέσεις.",
        "Μπορείτε να ξανακάνετε αίτηση όταν ανοίξουν νέες θέσεις.",
        "Θα προσέχουμε ευκαιρίες που ταιριάζουν σε εσάς.",
    ],
    "closing": ["Με εκτίμηση,", "Με θερμούς χαιρετισμούς,", "Ευχαριστώ,", "Με σεβασμό,"],
    "titles": [
        "Υπεύθυνος Προσλήψεων",
        "Talent Acquisition",
        "Υπεύθυνος Προσλήψεων",
        "Συντονιστής Ανθρωπίνων Πόρων",
    ],
    "neg": {
        "application_ack": {
            "subject": ["Λάβαμε την αίτησή σας", "Η αίτηση ελήφθη - {position}"],
            "intro": ["Γεια σας {first},", "Αγαπητέ υποψήφιε,"],
            "core": [
                "Ευχαριστούμε για την αίτηση για τη θέση {position} στην {company}· λάβαμε την αίτησή σας.",
                "Η αίτησή σας για τη θέση {position} (ID {id}) ελήφθη και βρίσκεται υπό εξέταση.",
            ],
            "extra": [
                "Μπορείτε να βλέπετε την κατάστασή σας οποιαδήποτε στιγμή στην πύλη.",
                "Αυτό το ταχυδρομείο δεν ελέγχεται· παρακαλώ μην απαντάτε.",
            ],
        },
        "interview_invite": {
            "subject": ["Πρόσκληση σε συνέντευξη - {position}", "Επόμενο βήμα: ας μιλήσουμε"],
            "intro": ["Γεια σας {first},", "Αγαπητέ/η {name},"],
            "core": [
                "Θα θέλαμε να σας προσκαλέσουμε σε συνέντευξη 45 λεπτών για τη θέση {position}.",
                "Η ομάδα εκτίμησε την αίτησή σας και θέλει να προχωρήσει στο επόμενο βήμα.",
            ],
            "extra": [
                "Επιλέξτε ώρα μέσω του παρακάτω συνδέσμου.",
                "Η συνέντευξη θα αφορά την εμπειρία σας στο {skill}.",
            ],
        },
        "offer_letter": {
            "subject": [
                "Προσφορά εργασίας - {company}",
                "Θέλαμε να σας προσφέρουμε τη θέση {position}",
            ],
            "intro": ["Αγαπητέ/η {name},"],
            "core": [
                "Χαιρόμαστε να σας προσφέρουμε τη θέση {position} στην {company}.",
                "Μετά από επιτυχή τελικό γύρο, θέλαμε να σας εντάξουμε στην ομάδα.",
            ],
            "extra": [
                "Οι λεπτομέρειες αμοιβής είναι συνημμένες· υπογράψτε έως τις {date}.",
                "Η ημερομηνία έναρξης είναι {date}.",
            ],
        },
        "job_alert": {
            "subject": ["Νέες θέσεις για εσάς", "Προτεινόμενες θέσεις"],
            "intro": ["Γεια σας {first},"],
            "core": [
                "Με βάση το προφίλ σας, επιλέξαμε μερικές νέες θέσεις.",
                "Η {company} προσλαμβάνει για αρκετές θέσεις· ρίξτε μια ματιά.",
            ],
            "extra": [
                "Για διαγραφή, πατήστε τον παρακάτω σύνδεσμο.",
                "Περισσότερες θέσεις στον ιστότοπό μας.",
            ],
        },
        "recruiter_spam": {
            "subject": ["Ας μιλήσουμε για νέες ευκαιρίες", "Το προφίλ σας τράβηξε την προσοχή μου"],
            "intro": ["Γεια σας {first},", "Γεια {first},"],
            "core": [
                "Είδα το προφίλ σας και θα ήθελα να σας μιλήσω για ευκαιρίες στον τομέα του {skill}.",
                "Προσλαμβάνουμε για αρκετές θέσεις και η εμπειρία σας ταιριάζει.",
            ],
            "extra": [
                "Ακόμη κι αν η στιγμή δεν είναι ιδανική, ας μείνουμε σε επαφή.",
                "Αν θέλετε, στείλτε μου το βιογραφικό σας.",
            ],
        },
        "newsletter": {
            "subject": ["Εβδομαδιαίο Καριέρας, τεύχος 128", "Οι συμβουλές καριέρας της εβδομάδας"],
            "intro": ["Γεια σας {first},"],
            "core": [
                "Καλώς ήρθατε στην εβδομαδιαία επισκόπηση του Εβδομαδιαίου Καριέρας.",
                "Αυτή την εβδομάδα: πώς διαπραγματεύεστε πακέτο μετακίνησης.",
            ],
            "extra": [
                "Προωθήστε το σε κάποιον που ψάχνει εργασία.",
                "Το λαμβάνετε επειδή είστε εγγεγραμμένοι.",
            ],
        },
        "account_security": {
            "subject": [
                "Νέα σύνδεση στον λογαριασμό σας",
                "Ειδοποίηση ασφαλείας: ασυνήθιστη δραστηριότητα",
            ],
            "intro": ["Γεια σας {first},"],
            "core": [
                "Εντοπίσαμε νέα σύνδεση στον λογαριασμό σας από νέα συσκευή.",
                "Κάποιος ζήτησε επαναφορά του κωδικού σας.",
            ],
            "extra": [
                "Αν δεν ήσασταν εσείς, ασφαλίστε αμέσως τον λογαριασμό.",
                "Μην μοιράζεστε ποτέ τους κωδικούς επαλήθευσης.",
            ],
        },
        "adversarial": {
            "subject": [
                "Η αίτησή σας απορρίφθηκε!",
                "Η πληρωμή απορρίφθηκε",
                "Re: η συνέντευξή σας αύριο",
            ],
            "intro": ["Γεια σας {first},", "Γεια {first},"],
            "core": [
                "Η αίτησή σας απορρίφθηκε! — πήρατε 2 στα 5 στο Interview Quest και η αίτησή σας "
                "μέσα στο παιχνίδι απορρίφθηκε. Δοκιμάζετε "
                "ξανά;",
                "Δυστυχώς δεν μπορούμε να ξεπεράσουμε το bonus υπογραφής· αλλά χαιρόμαστε να σας "
                "προσφέρουμε τη θέση "
                "{position}!",
                "Η τράπεζά σας απέρριψε την πληρωμή. Ενημερώστε την κάρτα σας για να κρατήσετε τη "
                "συνδρομή Premium στην "
                "{company}.",
                "Δυστυχώς η θέση {position} που αποθηκεύσατε στην {company} έκλεισε· δείτε πέντε παρόμοιες θέσεις.",
            ],
            "extra": [
                "Απαντήστε ΣΤΟΠ για διαγραφή.",
                "Τίποτα δεν άλλαξε στην πραγματική αίτησή σας.",
            ],
        },
    },
    "amb": {
        "keep_in_touch": {
            "subject": ["Ας μείνουμε σε επαφή", "Το προφίλ σας στην {company}"],
            "intro": ["Γεια σας {first},"],
            "core": [
                "Το προφίλ σας μας ενδιαφέρει και θα σας θυμόμαστε για μελλοντικές θέσεις.",
                "Ας μείνουμε σε επαφή· η ομάδα μπορεί να έχει ξανά ανάγκες το επόμενο τρίμηνο.",
            ],
            "extra": ["Επικοινωνήστε οποιαδήποτε στιγμή."],
        },
        "resume_on_file": {
            "subject": ["Η αίτησή σας στην {company}", "Το pool ταλέντων μας"],
            "intro": ["Αγαπητέ/η {name},"],
            "core": [
                "Το βιογραφικό σας προστέθηκε στο pool ταλέντων μας.",
                "Θα κρατήσουμε το βιογραφικό σας και θα επικοινωνήσουμε αν ανοίξει κατάλληλη θέση.",
            ],
            "extra": ["Δεν απαιτείται καμία ενέργεια από εσάς."],
        },
        "on_hold": {
            "subject": ["Ενημέρωση για τη θέση {position}", "Νέα προσλήψεων {company}"],
            "intro": ["Γεια σας {first},"],
            "core": [
                "Αποφασίσαμε να παύσουμε την πρόσληση για τη θέση {position}.",
                "Η θέση {position} είναι σε παύση έως την έγκριση προϋπολογισμού.",
            ],
            "extra": ["Θα επικοινωνήσουμε όταν αλλάξει η κατάσταση."],
        },
        "assessment": {
            "subject": ["Τα αποτελέσματα αξιολόγησης", "Η αξιολόγηση ολοκληρώθηκε"],
            "intro": ["Γεια σας {first},"],
            "core": [
                "Η βαθμολογία σας ήταν 62%· δυστυχώς δεν φτάσατε το όριο. Μπορείτε να ξαναδώσετε "
                "τη "
                "δοκιμασία μία "
                "φορά.",
                "Λυπούμαστε που το αποτέλεσμά σας ήταν κάτω από το όριο της διαδικασίας για {position}.",
            ],
            "extra": ["Τα αποτελέσματα είναι διαθέσιμα στην πύλη υποψηφίων."],
        },
    },
    "adv": {
        "subject": [
            "Πώς συντρίψαμε τις απορρίψεις στο JobHuntConf",
            "Η αίτησή σας απορρίφθηκε!",
            "Η πληρωμή απορρίφθηκε",
            "Η τέχνη της επιστολής απόρριψης",
        ],
        "intro": ["Γεια σας {first},", "Γεια {first},"],
        "core": [
            (
                "Η αίτησή σας απορρίφθηκε! — πήρατε 2 στα 5 στο Interview Quest και η αίτησή σας "
                "μέσα στο παιχνίδι απορρίφθηκε. Δοκιμάζετε "
                "ξανά;",
                "other",
            ),
            (
                "Δυστυχώς δεν μπορούμε να ξεπεράσουμε το bonus υπογραφής· αλλά χαιρόμαστε να σας "
                "προσφέρουμε τη θέση "
                "{position}!",
                "opportunity",
            ),
            (
                "Λυπούμαστε που το τεύχος είναι σύντομο· η σύνταξη μάζευε ιστορίες απορρίψεων των αναγνωστών.",
                "other",
            ),
            (
                "Δυστυχώς η θέση {position} που αποθηκεύσατε στην {company} έκλεισε· δείτε πέντε παρόμοιες θέσεις.",
                "other",
            ),
            (
                "Η συνέντευξη για τη θέση {position} επιβεβαιώθηκε για Τρίτη 14:00· ζητούμε "
                "συγνώμη "
                "για τη βλάβη του "
                "εργαλείου.",
                "opportunity",
            ),
        ],
        "extra": [
            "Απαντήστε ΣΤΟΠ για διαγραφή.",
            "Τίποτα δεν άλλαξε στην πραγματική αίτησή σας.",
            "Πλήρεις όροι στον ιστότοπό μας.",
        ],
    },
}

if set(BANKS) != {"en", "es", "zh", "hi", "ar", "fr", "bn", "pt", "ru", "ja", "de", "el"}:
    raise ValueError(f"unexpected bank languages: {sorted(BANKS)}")
