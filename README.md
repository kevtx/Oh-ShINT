# Oh-ShINT

Modern OSINT primitives for indicators of compromise (IOCs), with pluggable provider integrations, caching, and history tracking.

## What it does

- Lookup IOC reputations (IPv4, IPv6, CIDR, domain, MD5, SHA1, SHA256)
- Provide framework for easily adding new OSINT providers
- Caches HTTP responses (httpx + hishel)
- Stores query history in TinyDB for replay and auditing

## Providers

|Name|Status|
|-|-|
|AbuseIPDB|implemented|
|AlienVault OTX|scaffolded|
|VirusTotal|scaffolded|

Only AbuseIPDB implements request configuration at the moment; the others are placeholders awaiting API wiring.

## Requirements

- Python 3.12+
- Conda environment recommended (see environment.yml)

## Installation

Create the conda environment:

    conda env create -f environment.yml
    conda activate Oh-ShINT

## Configuration

Create a .env file in the project root with provider API keys. A template is provided in example.env.

Example:

    AbuseIPDB=your_abuseipdb_key
    AlienVault=your_otx_key
    VirusTotal=your_virustotal_key

## Usage (Python)

### Detect IOC type

    from OhShINT.models.ioc import IOC

    ioc = IOC("8.8.8.8")
    print(ioc) # 8.8.8.8

### Search with a provider

    from OhShINT.providers import AbuseIPDB

    provider = AbuseIPDB()
    result = provider.search("8.8.8.8", max_age_days=7)
    print(result)

### Use history (TinyDB)

    from OhShINT.history import History

    history = History(create=True)
    results = history.get("8.8.8.8", provider_name="AbuseIPDB")
    print(results)

## CLI / GUI

The CLI and GUI entry points are currently scaffolded but not wired. Expect these to change as provider coverage expands.

## Development

Run tests:

    python -m unittest

## Roadmap

- Implement request configs for AlienVault OTX and VirusTotal
- Re-enable CLI with pretty output and progress indicators
- Add batch IOC search
- Improve provider result normalization
