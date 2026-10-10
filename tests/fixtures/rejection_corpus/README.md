# Rejection detection test corpus

Fixture data for testing and evaluating the rejection-email detector in
`rejection-rejector`. All people, companies, and email addresses are fictional
(`example.com` domains only); the wording is modelled on real-world rejection,
ATS, and recruiting email phrasing.

## Files

| file | entries | purpose |
|---|---|---|
| `corpus.jsonl` | 240 | Evaluation corpus: ground-truth labels for measuring detection accuracy (precision/recall/F1 per label). |
| `training_corpus.jsonl` | 400 | Extra training data for a zero-false-positive classifier: 300 hard negatives plus 100 unusual-phrasing rejections. |

## Schema

Each line of both `.jsonl` files is one JSON object:

| field | type | notes |
|---|---|---|
| `id` | string | Unique: `R###` rejections, `N###` non-rejections, `A###` ambiguous (corpus); `H###` hard negatives, `P###` training positives (training file). |
| `label` | string | `rejection`, `not_rejection`, or `ambiguous`. |
| `subject` | string | Email subject line. |
| `body` | string | Plain-text email body, 80-400 words, with greeting and signature. |
| `industry` | string | Industry of the sending organisation. |
| `seniority` | string | Seniority of the role in question (`not_applicable` for non-job email). |
| `rejection_style` | string | Rejection style for rejections (e.g. `automated_ats`, `legal_formal`, `final_round_rejection`); content category for other entries (e.g. `interview_invite`, `event_cancellation`, `visa_sponsorship_refusal`). |
| `language` | string | `en`, `en-GB`, `de`, or `fr`. |
| `expects_reply` | bool | Whether a reasonable recipient would reply to challenge or follow up. |
| `purpose` | string | **training file only**: `training_hard_negative` or `training_positive`. |

## Label distribution

### corpus.jsonl (240 entries)

| label | count |
|---|---|
| rejection | 150 |
| not_rejection | 60 |
| ambiguous | 30 |

By language:

| language | count |
|---|---|
| en | 173 |
| en-GB | 31 |
| de | 21 |
| fr | 15 |

By `rejection_style`:

| rejection_style | count |
|---|---|
| automated_ats | 30 |
| personalized_recruiter | 30 |
| encouraging_feedback | 20 |
| application_acknowledgement | 14 |
| brief_blunt | 14 |
| final_round_rejection | 14 |
| interview_invite | 14 |
| legal_formal | 12 |
| panel_rejection | 12 |
| ghosting_followup_reply | 10 |
| recruiter_spam | 10 |
| assessment_request | 8 |
| hiring_freeze | 8 |
| internal_transfer | 8 |
| offer_letter | 8 |
| encouraging_noncommittal | 6 |
| newsletter | 6 |
| position_filled_keep_profile | 6 |
| vague_status_update | 6 |
| waitlist | 4 |

`expects_reply` is true for 79 rejections, 31 non-rejections, and
18 ambiguous entries.

### training_corpus.jsonl (400 entries)

| label | count |
|---|---|
| not_rejection | 300 |
| rejection | 100 |

| purpose | count |
|---|---|
| training_hard_negative | 300 |
| training_positive | 100 |

| language | count |
|---|---|
| en | 374 |
| en-GB | 14 |
| de | 6 |
| fr | 6 |

The 300 hard negatives (`label: not_rejection`)
carry rejection trigger words in non-rejection contexts: event/webinar
cancellations ("unfortunately we must cancel"), newsletters and blog digests
about rejection, gamified "your application was rejected" marketing, scheduling
emails ("unfortunately I can't make Tuesday"), rental and university application
rejections, conference talk rejections, refund denials, product order queue
"position filled" notices, dating-app notifications, HR surveys about rejected
candidates, and ATS stage-change notifications about a different candidate. The
100 training positives are clear job rejections with
unusual phrasings: scam/fake-recruiter rejections, internal mobility refusals,
union hiring-hall dispatch outcomes, civil-service sift/reserve-list letters,
apprenticeship refusals, visa sponsorship refusals, background-check failures,
reference-check outcomes, take-home assessment rejections, and "culture fit"
euphemisms.

## Evaluation usage

* Feed `subject` + `body` to the detector and compare its verdict with `label`;
  report precision/recall/F1 for `rejection` vs `not_rejection` (treating
  `ambiguous` as its own class or excluding it in strict mode).
* The `not_rejection` entries are false-positive probes: a working detector must
  not flag interview invitations, offers, acknowledgements, recruiter spam, or
  any of the `training_hard_negative` trigger-word decoys.
* `ambiguous` entries (role on hold, hiring freeze, "position filled but we'll
  keep your profile", vague status updates, encouraging non-answers) document
  cases where the detector may reasonably hesitate; use them to tune abstention
  behaviour rather than counting them as errors in either direction.
* `expects_reply` supports a second-stage test: if the detector decides to draft
  an assertive reply, it should only do so where `expects_reply` is true.
* `training_corpus.jsonl` is intended for fitting/calibrating the classifier
  (with the hard negatives as the critical class), while `corpus.jsonl` stays
  held out for evaluation only.
