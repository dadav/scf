# Getting Started

## Requirements

You need at least **python3.7** to use _scf_.

## Installation

_scf_ can be installed by running:

```bash
pip install python-scf
```

You can also install the package directly from the source repository:

```bash
pip install git+https://github.com/dadav/scf
```

## Getting Help

You can always use the integrated help functionality:

```{command-output} scf -h
```

## CLI

To get started, you could first fetch a list of all CVEs:

```{command-output} scf cve list
---
ellipsis: 5
---
```

The next thing you maybe want to try is, to get some more detailed informations
about this one specific CVE:

```{command-output} scf cve details CVE-2021-44832
---
ellipsis: 5
---
```

Ok great, now we want only the base score:

```{command-output} scf cve details CVE-2021-44832 --field cvss.score
```

You can even start a small API server:

```bash
scf server run
```

## Usage in python

```python
from scf.suse import get_cve_details

details = get_cve_details('CVE-2022-44832')
print(f'CVE Score: {details.cvss.score}')
```
