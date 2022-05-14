![PyPI - License](https://img.shields.io/pypi/l/python-scf)
[![Current version on PyPI](https://img.shields.io/pypi/v/python-scf)](https://pypi.org/project/python-scf/)
[![Lint/Build](https://github.com/dadav/scf/actions/workflows/build.yaml/badge.svg)](https://github.com/dadav/scf/actions/)
[![codecov](https://codecov.io/gh/dadav/scf/branch/main/graph/badge.svg?token=WPTU0RWTZ6)](https://codecov.io/gh/dadav/scf)

![Homedir](./img/scf.png)

> SUSE CVE Fetcher (unofficial; not developed by SUSE)

scf is a small tool to fetch informations about CVEs from suse.com.

## ⏬ Installation

Install via `pypi` package:

```bash
pip install python-scf
```

Or directly via source:

```bash
pip install git+https://github.com/dadav/scf
```

## 📙 Documentation

👉 Please use [https://scf.readthedocs.io/en/latest/](https://scf.readthedocs.io/en/latest/)

## ⭐️ Usage

You can use it via command line:

```bash
# list all cve
scf cve list

# export as json
scf cve list --json

# fetch details for a specific cve
scf cve details CVE-2022-0001

# start a little api server
scf server run

# prefetch some data (older years are excluded)
scf cache populate

# show some stats about the local cache
scf cache stats
```

Or in your python program:

```python
from rich import print
from scf.suse import get_all_cve, get_cve_details

latest_cve = get_all_cve()[0]
details = get_cve_details(latest_cve)
print(f'[{latest_cve}] Score: {details.cvss.score}')
```

## 💓 Contributors

<img src="https://contrib.rocks/image?repo=dadav/scf" />

> Made with [contributors-img](https://contrib.rocks).
