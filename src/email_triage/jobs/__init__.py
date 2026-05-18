"""Background-job handlers that aren't the bulk triage runner.

The legacy ``run_triage_all`` (whole-mailbox classify+act sweep) and
``run_style_mine_job`` (M-3 distill) live in
``email_triage.web.triage_runner_bulk`` for historical reasons. New
job kinds with self-contained workloads go here so the dispatcher in
triage_runner_bulk stays a thin switch.

Public modules:
  * :mod:`embedding_reindex` — re-embed an account's sent_mail_index
    rows after an embedding-backend switch.
"""
