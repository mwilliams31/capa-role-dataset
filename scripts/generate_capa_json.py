
"""
This script processes sample files in a specified directory using the capa tool and generates JSON output files.
In order for generate_dataset_files.py to work as expected, sample files should be named using their SHA256 hash value.

Usage:
    python generate_capa_json.py <samples_directory>
    samples_directory (str): The directory containing the sample files to be processed.

Example:
    python generate_capa_json.py /path/to/samples
"""
import os
import asyncio
import argparse


async def run_capa(file_path: str, semaphore: asyncio.Semaphore) -> bool:
    """Run the capa tool on a given file asynchronously.
    
    Args:
        file_path (str): The path to the file to be processed by capa.
        semaphore (asyncio.Semaphore): A semaphore to limit the number of concurrent capa processes.
    
    Returns:
        bool: True if the file was processed successfully, False otherwise.
    """
    command = f"./capa --os windows -j {file_path}"
    print(f"Processing {file_path}")
    
    async with semaphore:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            print(f"Error processing {file_path}")
            print(stderr.decode())
            return False
        else:
            output_path = f"{file_path}.json"
            with open(output_path, "w") as output_file:
                output_file.write(stdout.decode())
            
            print(f"Processed {file_path}")
            return True


async def run_capa_on_samples(samples_dir: str) -> None:
    """Run capa on all samples in the specified directory.
    
    This function walks through the given directory, processes each file (excluding JSON files) 
    using capa, and limits the number of concurrent tasks to 5. It prints the total 
    number of samples processed at the end.
    
    Args:
        samples_dir (str): The directory containing the sample files to be processed.
    
    Returns:
        None
    """
    samples_processed = 0
    tasks = []
    semaphore = asyncio.Semaphore(5)  # Limit to 5 concurrent tasks
    
    for root, _, files in os.walk(samples_dir):
        for file in files:
            # Ignore existing JSON files
            if file.endswith(".json"):
                continue
            
            file_path = os.path.join(root, file)
            tasks.append(run_capa(file_path, semaphore))
    
    results = await asyncio.gather(*tasks)
    samples_processed = sum(results)
    
    print(f"Processed {samples_processed} samples")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate capa JSON files from samples")
    parser.add_argument("samples_directory", help="Directory containing the samples")
    args = parser.parse_args()

    asyncio.run(run_capa_on_samples(args.samples_directory))
