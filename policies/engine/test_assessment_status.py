from policies.engine.assessment_status import compute_assessment_status


def test_no_jobs_yet_is_queued():
    assert compute_assessment_status([]) == "queued"


def test_all_pending_is_queued():
    assert compute_assessment_status(["pending", "pending"]) == "queued"


def test_any_running_is_running():
    assert compute_assessment_status(["pending", "running"]) == "running"


def test_any_awaiting_finding_is_running():
    # The collector finished but a human hasn't recorded a finding yet -
    # the assessment isn't done.
    assert compute_assessment_status(["recorded", "awaiting_finding"]) == "running"


def test_mixed_pending_and_awaiting_finding_is_running():
    assert compute_assessment_status(["pending", "awaiting_finding"]) == "running"


def test_all_recorded_is_completed():
    assert compute_assessment_status(["recorded", "recorded", "recorded"]) == "completed"


def test_all_failed_is_failed():
    assert compute_assessment_status(["failed", "failed"]) == "failed"


def test_mix_of_recorded_and_failed_is_partially_completed():
    assert compute_assessment_status(["recorded", "failed"]) == "partially_completed"


def test_single_recorded_job_is_completed():
    assert compute_assessment_status(["recorded"]) == "completed"


def test_cancelled_always_wins_over_job_statuses():
    assert compute_assessment_status(["running", "pending"], cancelled=True) == "cancelled"
    assert compute_assessment_status(["recorded", "failed"], cancelled=True) == "cancelled"
    assert compute_assessment_status([], cancelled=True) == "cancelled"


def test_partially_completed_is_not_reached_while_anything_is_still_in_progress():
    # A recorded + failed + still-running mix must read as running, not
    # partially_completed, until every job has actually finished.
    assert compute_assessment_status(["recorded", "failed", "running"]) == "running"
