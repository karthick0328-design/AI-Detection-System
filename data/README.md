# Phishing & Benign URLs Dataset

## Dataset Information
- **Source**: Curated academic benchmark dataset hosted at HuggingFace (`Mitake/PhishingURLsANDBenignURLs`), integrating verified records from PhishTank, OpenPhish, and Tranco / Alexa top legitimate domains.
- **License**: Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA-4.0).
- **Format**: CSV (`url`, `label`)
  - `0`: Legitimate (Benign) website URL
  - `1`: Phishing website URL

## Downloading the Dataset
To download the verified dataset for model training, run:
```bash
python src/download_data.py
```
This script downloads `PhishBenignDataset.csv` directly from HuggingFace to `data/dataset.csv` with integrity and column structure checks.

## Automated Test Fixture
`data/test_fixture.csv` is a static, balanced 50-record fixture provided strictly for automated unit and integration tests (`pytest`). It ensures unit tests run quickly, predictably, and offline without requiring network downloads.
