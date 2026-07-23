"""The single centralized computer of an assessment's aggregate status.

An assessment groups a batch of scan_jobs launched together (e.g. Run Scan's
"Run selected"). Its status is never hand-set by the API beyond the two
explicit actions (queued at creation, cancelled on request) - everything else
is derived here, from the current statuses of its child scan_jobs, so the API
and UI never duplicate this logic.

`awaiting_finding` counts as still in progress, not terminal: the collector
has finished, but a human hasn't yet recorded a finding for it, so the
assessment as a whole isn't done.
"""

from typing import Literal

AssessmentStatus = Literal["queued", "running", "partially_completed", "completed", "failed", "cancelled"]

IN_PROGRESS_JOB_STATUSES = {"pending", "running", "awaiting_finding"}
TERMINAL_JOB_STATUSES = {"recorded", "failed"}


def compute_assessment_status(job_statuses: list[str], *, cancelled: bool = False) -> AssessmentStatus:
    """job_statuses is every child scan_job's current status.

    `cancelled` is set explicitly by the caller (never inferred from job
    statuses) and always wins - a cancelled assessment stays cancelled
    regardless of what its already-dispatched jobs go on to do.
    """
    if cancelled:
        return "cancelled"
    if not job_statuses or all(status == "pending" for status in job_statuses):
        return "queued"
    if any(status in IN_PROGRESS_JOB_STATUSES for status in job_statuses):
        return "running"
    # Every job has reached a terminal state (recorded or failed).
    if all(status == "recorded" for status in job_statuses):
        return "completed"
    if all(status == "failed" for status in job_statuses):
        return "failed"
    return "partially_completed"
