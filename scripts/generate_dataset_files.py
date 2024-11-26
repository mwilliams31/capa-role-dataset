"""
This script processes JSON output files from capa to generate dataset files. It reads JSON files from a specified directory,
extracts unique rules and sample results, and generates two CSV files: one containing rule IDs, namespaces, and rule names,
and another containing each sample's SHA256 hash and a binary indicator for each rule ID.

Usage:
    python generate_dataset_files.py <results_directory> [-v | --verbose]
Args:
    results_directory (str): The directory containing JSON output files from capa.
    -v, --verbose (bool): Optional; if set, prints capa rules for all files.
"""

import argparse
import pandas as pd
import capa.render.result_document

from typing import Tuple
from pathlib import Path

def generate_samples_df(sample_results: dict, rules_df: pd.DataFrame) -> pd.DataFrame:
    """Generates a DataFrame of samples with rule matches.
    
    Args:
        sample_results (dict): A dictionary where keys are sample identifiers (e.g., sha256 hashes) 
            and values are lists of tuples, each containing a namespace and rule name.
        
        rules_df (pd.DataFrame): A DataFrame containing rule information with columns 'namespace' 
            and 'rule_name', and indexed by rule IDs.
    
    Returns:
        pd.DataFrame: A DataFrame where rows correspond to samples and columns correspond to rule IDs. 
            The DataFrame is filled with 1s and 0s indicating the presence or absence of rule matches 
            for each sample.
    """
    samples_df = pd.DataFrame(columns=['sha256'] + rules_df.index.tolist())
    samples_df['sha256'] = sample_results.keys()
    samples_df.set_index('sha256', inplace=True)
    samples_df.fillna(0, inplace=True)
    for sample in sample_results:
        for capa in sample_results[sample]:
            namespace, rule_name = capa
            
            # Find the rule_id for the given namespace and rule_name
            rule_id = rules_df[(rules_df['namespace'] == namespace) & (rules_df['rule_name'] == rule_name)].index[0]
            if rule_id is not None:
                # Set the rule_id to 1 for the given sample
                samples_df.loc[sample, rule_id] = 1
            else:
                print(f"Rule not found: {capa}")
                continue

    return samples_df


def generate_rules_df(unique_rules: list) -> pd.DataFrame:
    """Generates a DataFrame from a list of unique rules.

    Args:
        unique_rules (list): A list of unique rules, where each rule is a tuple containing 
                             the namespace and rule name.

    Returns:
        pd.DataFrame: A DataFrame with columns "namespace" and "rule_name", sorted by these columns,
                      and with an index named "rule_id".
    """

    rules_df = pd.DataFrame(unique_rules, columns=["namespace", "rule_name"])
    rules_df.sort_values(by=["namespace", "rule_name"], inplace=True)
    rules_df.reset_index(drop=True, inplace=True)
    rules_df.index.name = "rule_id"

    return rules_df


def print_capas(sha256: str, sample_capas: set):
    """Print the capas for a given sample."""

    print(f"Sample: {sha256}\n")
    rule_hits = []
    for namespace, rule_name in sample_capas:
        rule_hits.append(f"{namespace}/{rule_name}")
    
    for rule in sorted(rule_hits):
        print(rule)


def parse_results_json_files(results_directory: str, verbose: bool=False) -> Tuple[list, dict]:
    """Parses JSON files in the specified directory to extract unique rules and sample results.
    
    This function processes JSON files in the given directory, ensuring that filenames match the expected SHA256 hash format.
    It parses each JSON file into a ResultDocument, extracts metadata and capabilities, and collects unique rules and sample results.
    
    Args:
        results_directory (str): The directory containing JSON files to be processed.
        verbose (bool, optional): If True, prints the capas for each processed file. Defaults to False.
    
    Returns:
        Tuple[list, dict]: A tuple containing:
            - A list of unique rules found across all JSON files.
            - A dictionary mapping each sample's SHA256 hash to a list of tuples, where each tuple contains a namespace and rule name.
    """
    unique_rules = set()
    sample_results = {}     # {sha256: [(namespace, rule_name), ...]}

    print(f"Processing JSON files in {results_directory} ...")
    for path in Path(results_directory).rglob("*.json"):
        if verbose:
            print(f"\nProcessing {path.name}")

        # Ensure filename matches SHA256 hash length
        if len(Path(path).stem) != 64:
            print("Unexpected filename: %s" % path)
            continue

        # Ensure filename contains only hex characters
        if not all(c in "0123456789abcdef" for c in Path(path).stem):
            print("Unexpected filename: %s" % path)
            continue
        
        # Parse JSON file into a ResultDocument
        try:
            result_doc = capa.render.result_document.ResultDocument.from_file(path)
        except Exception as e:
            print(f"Error parsing JSON file {path}: {e}")
            continue

        # Convert the ResultDocument to metadata and capabilities
        meta, capabilities = result_doc.to_capa()

        # Confirm the sample sha256 from the JSON meta field matches the filename
        if meta.sample.sha256 != Path(path).stem:
            print("Unexpected sample sha256 for file: %s" % path)
            continue
        
        # Extract capa hits from the ResultDocument 
        sample_capas = set()
        for rule_name in capabilities.keys():
            rule = result_doc.rules[rule_name]
            
            # Ignore library rules and subscope rules
            if rule.meta.lib:
                continue
            if rule.meta.is_subscope_rule:
                continue
            
            # Extract namespace and rule name
            namespace = rule.meta.namespace
            if namespace is None:
                namespace = "unknown"
            rule_name = rule_name
            
            # Add tuple of namespace and rule_name to unique_rules and sample_capas
            unique_rules.add((namespace, rule_name))
            sample_capas.add((namespace, rule_name))
        
        # Add sample_capas to sample_results dictionary
        sample_results[meta.sample.sha256] = list(sample_capas)
        
        if verbose:
            print(f"Successfully processed {path.name}\n")
            print_capas(meta.sample.sha256, sample_capas)
    
    return list(unique_rules), sample_results



def main():
    parser = argparse.ArgumentParser(
        description="""
        Generate dataset files given a directory that contains JSON output files from capa. 
        JSON files must have a .json extension and a filename that matches the SHA256 hash of the sample they represent.
        """
    )
    parser.add_argument("results_directory", type=str)
    parser.add_argument("-v", "--verbose", action="store_true", help="Print capas for all files")
    args = parser.parse_args()

    # Retrieve a list of unique rules and a dictionary of samples and their capa rule hits
    unique_rules, sample_results = parse_results_json_files(args.results_directory, verbose=args.verbose)
    
    # Generate CSV file that contains a rule ID, namespace, and rule name for each unique rule
    rules_df = generate_rules_df(unique_rules)
    print(f"\nWriting {len(rules_df)} unique rules to rule_ids.csv")
    rules_df.to_csv("rule_ids.csv")

    # Generate CSV file that contains each sample's SHA256 hash and a 1 or 0 for each rule ID
    samples_df = generate_samples_df(sample_results, rules_df)
    print(f"Writing capa results data for {len(samples_df)} samples to samples.csv")
    samples_df.to_csv("samples.csv")


if __name__ == "__main__":
    main()
