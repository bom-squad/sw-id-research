# Software Identifiers Research

This repo is dedicated to scripts and data supporting developing software identifiers tranlators.


## PURL to CPE for open source vulnerabilities

### Mapping purls to cpes by joining osv and nvd databases on cve-id

Mapping has been done for osv PyPI vulnerabilities. 

Mapping resutls are in purl2cpe-mapping.csv

Some insights from the mapping:

- The mappings are not trivial; 
    - there are only 9 cpes with the prefix  ```cpe:2.3:a:pypi:```.
    - django, for example, has cpes such as "cpe:2.3:a:ubuntu...". This does make sence from NVDs point of view, since NVD aims at mapping vulnerable applications, not only packages. But translating th django purl to an ubuntu cpe is not a viable solution (it will cause false positives).
- only about 2/3 of osv python vulnerabilities have a cve-id. This should raise the concern if, given someone has purls using the nvd database is the right approach.
- There may be NVD entries with no cpes, and actually no data at all. for example: [CVE-2022-3102](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-3102) gave the following results:


```
{
"resultsPerPage": 0,
"startIndex": 0,
"totalResults": 0,
"format": "NVD_CVE",
"version": "2.0",
"timestamp": "2023-06-17T19:19:50.057",
"vulnerabilities": []
}
```

### Generate a purl-cpe database by joining osv and nvd databases

- download portions of the osv data base to the osv folder.

- run ```python osv2csv.py``` to create:
    - a csv file with purl and reference data.
    - a text file with the list of cves found.

- run ```python cve2csv.py``` to create:
    - a csv file with cpes for the cves in the above files.

- run ```python cvs2db.py``` to upload a csv to a database

## Data sources
CVE data is from NVD.
OSV data is from Google's OSV database (downloaded from gcloud bucket)