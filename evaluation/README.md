## Evaluation

The `evaluation/` directory contains SHA256 hashes of applications used in our evaluation experiments.

### Dataset Sources

- **Malware (Evaluation 1 & 2)**: The malware samples used in Evaluation 1 and 2 are from the dataset provided in "Rotten apples spoil the bunch: an anatomy of Google Play malware (ICSE'22)". The malware dataset can be obtained by contacting the authors of this paper.

- **Benign Applications**: Applications used in other evaluations are sourced from the [AndroZoo dataset](https://androzoo.uni.lu/). The SHA256 hashes of these applications are listed in `evaluation/benigns.txt`.

### Application Selection Criteria

For benign applications from AndroZoo, we applied the following selection criteria:

1. **Metadata Filtering**: We filtered applications based on metadata from `latest.csv.gz`:
   - `dex_date`: Used to ensure applications are recent
   - `vt_detection`: Used to filter out potentially malicious applications

2. **Popularity-based Selection**: From `gp-metadata-aggregate.jsonl.gz`, we selected applications with the highest `max_nb_downloads` (maximum number of downloads from Google Play Store) to ensure we evaluate popular, real-world applications.

For detailed information about AndroZoo metadata fields, please refer to the [AndroZoo documentation](https://androzoo.uni.lu/).