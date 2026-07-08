import glob

from policies.engine.policy_engine import load_control
from policies.schema.validate import validate_control


def test_all_five_controls_are_schema_valid():
    control_files = sorted(glob.glob("policies/controls/SA-IOT-*.yaml"))
    assert len(control_files) == 5
    for path in control_files:
        control = load_control(path)
        validate_control(control)  # should not raise


def test_control_ids_match_filenames():
    control_files = sorted(glob.glob("policies/controls/SA-IOT-*.yaml"))
    for path in control_files:
        control = load_control(path)
        expected_id = path.split("/")[-1].replace(".yaml", "").replace("\\", "/").split("/")[-1]
        assert control["control_id"] == expected_id
