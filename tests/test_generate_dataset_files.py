import pandas as pd

from pathlib import Path
from scripts.generate_dataset_files import generate_samples_df, generate_rules_df, parse_results_json_files

def test_generate_samples_df():
    sample_results = {
        "sample1": [("namespace1", "rule1"), ("namespace2", "rule2")],
        "sample2": [("namespace1", "rule1")]
    }
    rules_df = pd.DataFrame({
        "namespace": ["namespace1", "namespace2"],
        "rule_name": ["rule1", "rule2"]
    })
    rules_df.index.name = "rule_id"
    rules_df.index = [0, 1]

    expected_df = pd.DataFrame({
        "sha256": ["sample1", "sample2"],
        0: [1, 1],
        1: [1, 0]
    }).set_index("sha256")

    result_df = generate_samples_df(sample_results, rules_df)
    pd.testing.assert_frame_equal(result_df, expected_df)

def test_generate_rules_df():
    unique_rules = [("namespace1", "rule1"), ("namespace2", "rule2")]
    expected_df = pd.DataFrame({
        "namespace": ["namespace1", "namespace2"],
        "rule_name": ["rule1", "rule2"]
    })
    expected_df.index.name = "rule_id"

    result_df = generate_rules_df(unique_rules)
    pd.testing.assert_frame_equal(result_df, expected_df)

def test_parse_results_json_files(tmp_path: Path):
    unique_rules, sample_results = parse_results_json_files("./tests/test_data")

    expected_unique_rules = [('executable/pe/pdb', 'contains PDB path'), ('host-interaction/network/traffic/filter', 'register network filter via WFP API'), ('host-interaction/thread/create', 'create thread'), ('host-interaction/network/traffic/filter', 'delete network filter via WFP API'), ('host-interaction/registry/create', 'set registry value')]
    expected_sample_results = {'e8e7f2f889948fd977b5941e6897921da28c8898a9ca1379816d9f3fa9bc40ff': [('executable/pe/pdb', 'contains PDB path'), ('host-interaction/network/traffic/filter', 'register network filter via WFP API'), ('host-interaction/thread/create', 'create thread'), ('host-interaction/network/traffic/filter', 'delete network filter via WFP API'), ('host-interaction/registry/create', 'set registry value')]}

    assert sorted(unique_rules) == sorted(expected_unique_rules)
    
    expected_sample_results["e8e7f2f889948fd977b5941e6897921da28c8898a9ca1379816d9f3fa9bc40ff"].sort()
    sample_results["e8e7f2f889948fd977b5941e6897921da28c8898a9ca1379816d9f3fa9bc40ff"].sort()
    assert sample_results == expected_sample_results
    