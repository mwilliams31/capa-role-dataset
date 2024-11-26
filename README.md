# capa-role Dataset

## Executive Summary
Malware reverse engineers are commonly tasked with determining a sample’s capabilities and purpose. Fortunately, a tool named [`capa`](https://github.com/mandiant/capa) can automatically identify capabilities by analyzing a sample’s characteristics, code, and behavior. However, interpreting `capa` results may be difficult for those not well-versed in malware behavior. In some cases, an analyst may be less interested in individual capabilities and simply want to determine a sample’s primary functionality, or _role_. Example roles include backdoor, credential stealer, and ransomware. The motivation behind this dataset is to collect `capa` results for samples with various roles so that a machine-learning model can be trained to determine the likely role for a given sample based on its `capa` results.

What sets this dataset apart from the datasets highlighted below (and others) is its focus on determining a malware sample's role, as opposed to labeling a malware family or determining if a file is malicious based on static features or dynamic behavior. There also does not appear to be a publicly available dataset centered around `capa` results.

## Navigating This Repository
After reviewing the documentation below, use the following folders to navigate the repository:
* The [`scripts`](scripts) directory contains:
  * Script used to the generate capa results
  * Script that generates dataset files based on the raw capa results
* The [`dataset`](dataset) directory contains:
  * Raw dataset files
  * Raw CAPA results
  * Jupyter notebook that explores the dataset
  * Additional metadata for each of the samples in the dataset

## Notable Malware Analysis Datasets
The datasets listed below were created to aid malware analysis and detection research.
* [Avast-CTU Public CAPEv2 Dataset](https://github.com/avast/avast-ctu-cape-dataset)
  * Contains [CAPEv2 sandbox](https://capev2.readthedocs.io/en/latest/) reports for 48,976 malicious files.
  * Enables researchers to train on _dynamic_ analysis results rather than _static_.
  * Samples labeled using one of six malware "types" (`"banker", "trojan", "pws", "coinminer", "rat", "keylogger"`) and one of ten malware families.
    * "Types" align with "roles" in the current dataset. 
* [Elastic Malware Benchmark for Empowering Researchers (EMBER)](https://github.com/elastic/ember)
  * Includes static features extracted from 1.1M Windows PE files scanned in or before 2018.
  * Utilized the [LIEF project](https://lief.re/) to extract features.
* [Malware Open-source Threat Intelligence Family (MOTIF) Dataset](https://github.com/boozallen/MOTIF)
  * Contains 3,095 disarmed PE malware samples from 454 malware families.
  * Family labels obtained from open-source threat intelligence reports published by 14 cybersecurity firms between 01/01/2016 and 01/01/2021.
  * Contains EMBER raw features for each sample.

## Power Analysis
The following Python snippet illustrates how the required sample size was computed prior to collection:
```Python
effect_size = 0.5  # Medium effect size
alpha = 0.05       # Significance level
power = 0.8        # Desired power

analysis = TTestIndPower()
sample_size = analysis.solve_power(effect_size=effect_size, 
                                   alpha=alpha, 
                                   power=power, 
                                   alternative='two-sided')

print(f"Required sample size: {sample_size:.1f}")
```

Output: `Required sample size: 63.8`

## Data Collection
The collection protocol involved reviewing open-source threat intelligence reports to identify Windows PE sample hashes and, more importantly, the role label applied to a given sample. For the list of roles included in this dataset, see the [Roles](#roles) section below. When a sample hash with an associated role was identified, VirusTotal's Behavior tab ([example](https://www.virustotal.com/gui/file/421b71ac924938e9b47291f38233d9e4b8116c1f4ec8db523d229535c8c12212/behavior)) was reviewed to determine if 1) the file is in the public domain and 2) the sample produced an acceptable number of capa rule hits (roughly 5 or more).  

After identifying a candidate sample, the sample's hash was looked up on the following public malware repositories: 

* [VX Underground](https://vx-underground.org/)
* [MalwareBazaar](https://bazaar.abuse.ch/)
* [capa-testfiles repository](https://github.com/mandiant/capa-testfiles)
* [Virus.exchange](https://virus.exchange/) (requires registration)

If a candidate sample was found on any of the above sites, it was downloaded and utilized to build this dataset. Note, the actual samples are _not_ part of the dataset. For each downloaded sample, capa results were generated using the [`generate_capa_json.py` script](/scripts/generate_capa_json.py) and the [capa version `7.4.0`](https://github.com/mandiant/capa/releases/tag/v7.4.0) binary. The JSON results were parsed using the [`generate_dataset_files.py` script](/scripts/generate_dataset_files.py), which generates the following files found in the [`dataset` directory](/dataset/):

* [samples.csv](/dataset/samples.csv) - a matrix that lists each sample's SHA256 hash and capa rule hits
* [rule_ids.csv](/dataset/rule_ids.csv) - mapping of rule IDs to their rule namespace and name

An additional CSV file named [sample_roles.csv](/dataset/sample_roles.csv) completes the dataset. It contains the role label assigned to each sample based on the review of open-source intelligence reports.

### Limitations
Without access to a tool such as [VirusTotal Intelligence](https://www.virustotal.com/gui/intelligence-overview), identifying and collecting malware samples with documented role labels proved time-consuming and difficult. As a result, the sample size for this dataset is quite small at 58 samples, with a minimum of 5 samples for each of the 11 roles.

Another issue was the fact that numerous candidate samples were packed or heavily obfuscated. As a result, these samples often produced zero or few capa hits. Fortunately, capa now supports [extracting capabilities from sandbox runs](https://cloud.google.com/blog/topics/threat-intelligence/dynamic-capa-executable-behavior-cape-sandbox), but a CAPE instance was not created in the interest of time.

Finally, the dataset does not address every possible malware role. For example, coinminers are not represented in this dataset. The roles that _were_ selected (see the table below) hopefully represent a large portion of the malware encountered in the present day.

### Roles
The table below contains high-level descriptions for each _role_ label represented in the dataset:

| Role                  | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **Backdoor**          | Provides a threat actor with interactive control over a system.   |
| **Downloader**        | Downloads, and likely executes, an additional malicious payload.           |
| **Dropper**           | Writes an embedded payload to the filesystem and likely executes it.        |
| **Dropper (memory-only)** | Executes an embedded payload in memory.                                    |
| **Infostealer**       | Collects user data, including credentials, and may upload the data to a remote server. |
| **Keylogger**         | Captures user keystrokes.                                                   |
| **Proxy Tool**        | Forwards malicious traffic through infected systems to disguise or anonymize activity. |
| **Ransomware**        | Encrypts files and demands payment in order to restore access.              |
| **Reconnaissance Tool** | Collects information about a system or network.                            |
| **Rootkit**           | Provides privileged access to a system and often hides itself or other malicious artifacts and activity. |
| **Wiper**             | Deletes or destroys data or systems.                                        |

## Dataset Tools
The [`scripts`](/scripts) directory contains the following scripts used to create the dataset:

* `generate_capa_json.py` - generate capa results for samples in a directory
* `generate_dataset_files.py` - parse the capa output and create two CSV files (`rule_ids.csv` and `samples.csv`)

## Exploratory Data Analysis
The [data_exploration.ipynb](/dataset/data_exploration.ipynb) Jupyter notebook contains the full results of data exploration. Here are some key takeaways:

* 319 capabilities were identified across 58 samples.
* Removing 31 inconsequential capabilities using domain knowledge and collapsing the remaining capabilities into their namespace reduced the feature set from 319 to 162.
  * Namespaces are the parent folder of each rule within the [`capa-rules` repository](https://github.com/mandiant/capa-rules). They act as a de facto category that contains one or more rules.
* Here are the top 10 selected namespaces based on chi-squared scores:

| Namespace                            |   Score |
|:-------------------------------------|--------:|
| host-interaction/os                  | 34.44   |
| impact/inhibit-system-recovery       | 31.8    |
| collection/database/sql              | 31.8    |
| data-manipulation/encryption/dpapi   | 31.8    |
| linking/static/sqlite3               | 31.8    |
| data-manipulation/hashing/sha224     | 25      |
| data-manipulation/encryption/rsa     | 25      |
| data-manipulation/hashing/sha256     | 25      |
| host-interaction/gui/window/get-text | 24.61 |
| collection/credit-card               | 24.52 |

* Here are the top 5 namespaces for each role based on a random forest classifer:

Role: rootkit
| Namespace                               |   Importance |
|:----------------------------------------|-------------:|
| host-interaction/driver                 |    0.157046  |
| host-interaction/network/traffic/filter |    0.0801488 |
| linking/static/msdetours                |    0.0677861 |
| host-interaction/os/info                |    0.0555469 |
| host-interaction/process/terminate      |    0.0508417 |

Role: dropper
| Namespace                        |   Importance |
|:---------------------------------|-------------:|
| linking/static/zlib              |    0.109504  |
| host-interaction/gui/window/hide |    0.0469539 |
| executable/resource              |    0.0450376 |
| data-manipulation/checksum/crc32 |    0.0435516 |
| host-interaction/service/stop    |    0.0425476 |

Role: backdoor
| Namespace                           |   Importance |
|:------------------------------------|-------------:|
| host-interaction/file-system/exists |    0.0980865 |
| communication/http                  |    0.0583574 |
| host-interaction/process/inject     |    0.0512637 |
| communication/tcp/client            |    0.0453538 |
| host-interaction/process/create     |    0.0345321 |

Role: infostealer
| Namespace                               |   Importance |
|:----------------------------------------|-------------:|
| data-manipulation/hashing               |    0.0560147 |
| host-interaction/gui/window/find        |    0.0558326 |
| data-manipulation/checksum/luhn         |    0.045333  |
| host-interaction/file-system/create     |    0.0443773 |
| host-interaction/file-system/files/list |    0.0415506 |

Role: reconnaissance tool
| Namespace                  |   Importance |
|:---------------------------|-------------:|
| communication/socket       |    0.073244  |
| host-interaction/accounts  |    0.0660904 |
| data-manipulation/prng/lcg |    0.061476  |
| host-interaction/user      |    0.0575969 |
| host-interaction/process   |    0.0558216 |

Role: downloader
| Namespace                      |   Importance |
|:-------------------------------|-------------:|
| communication/http/client      |    0.072708  |
| host-interaction/session       |    0.0657982 |
| data-manipulation/hashing/fnv  |    0.0561454 |
| communication/c2/file-transfer |    0.0546037 |
| communication/http             |    0.0489487 |

Role: dropper memory-only
| Namespace                          |   Importance |
|:-----------------------------------|-------------:|
| load-code/shellcode                |    0.083126  |
| host-interaction/file-system/write |    0.0743579 |
| host-interaction/file-system/read  |    0.0643555 |
| host-interaction/process/terminate |    0.0636884 |
| host-interaction/process/inject    |    0.0630798 |

Role: wiper
| Namespace                               |   Importance |
|:----------------------------------------|-------------:|
| impact/wipe-disk                        |    0.111038  |
| host-interaction/os                     |    0.0671408 |
| host-interaction/domain                 |    0.0367361 |
| persistence/service                     |    0.0361436 |
| host-interaction/file-system/files/list |    0.0345633 |

Role: ransomware
| Namespace                            |   Importance |
|:-------------------------------------|-------------:|
| impact/inhibit-system-recovery       |    0.133496  |
| data-manipulation/encryption/rsa     |    0.0829207 |
| host-interaction/process/inject      |    0.035089  |
| data-manipulation/encryption/salsa20 |    0.0340129 |
| anti-analysis/anti-forensic          |    0.0309968 |

Role: proxy tool
| Namespace                        |   Importance |
|:---------------------------------|-------------:|
| communication/socket             |    0.066684  |
| communication/socket/tcp         |    0.0567162 |
| communication/tcp/client         |    0.0456773 |
| data-manipulation/hashing/sha256 |    0.0448028 |
| data-manipulation/hashing/sha224 |    0.0380187 |

Role: keylogger
| Namespace                            |   Importance |
|:-------------------------------------|-------------:|
| host-interaction/gui/window/get-text |    0.0995472 |
| collection/keylog                    |    0.0793715 |
| host-interaction/hardware/keyboard   |    0.0663564 |
| host-interaction/clipboard           |    0.0477662 |
| host-interaction/file-system/delete  |    0.037909  |

Most, if not all, of the selected features make sense for the given role. Their relative importance is also reasonable in most cases. For example:
* The `host-interaction/driver` namespace scored well above the rest for rootkits.
* The `impact/inhibit-system-recovery` namespace scored well above the rest for ransomware.
* The `impact/wipe-disk` namespace scored well above the rest for wipers.

## Downloading the Dataset
The dataset's CSV files can be downloaded from the [`dataset`](/dataset) directory or [Hugging Face](https://huggingface.co/datasets/mwilliams31/capa-role). A ZIP of the raw capa JSON output can be downloaded from [`/dataset/capa-results-json.zip`](/dataset/capa-results-json.zip) as well as [Hugging Face](https://huggingface.co/datasets/mwilliams31/capa-role).

## Ethics Statement
The dataset is comprised primarily of JSON files and CSV files derived from those JSON files. The JSON files were produced by the `capa` malware analysis tool. These results are not associated with specific individuals or entities. As such, there are no ethical concerns related to privacy, data protection, or potential misuse. The dataset is intended for cybersecurity research and analysis.

## License
This dataset is licensed under the [Creative Commons Zero v1.0 Universal](LICENSE) license.

## Acknowledgement
I'd like to acknowledge Jay Gibble, who provided the inspiration for creating this dataset.
