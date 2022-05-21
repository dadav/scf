"""
Contains the code to fetch the informations from suse.com
"""
import re
from typing import Dict, DefaultDict
from pathlib import Path
from datetime import timedelta
from collections import defaultdict
from requests_cache import CachedSession
from bs4 import BeautifulSoup
from scf.config import settings
from scf.models import CVE, SimplifiedRating, CVSS, CVSSVector, State, Product, OverallState
from scf.utils import numeric


SUSE_CVE_LIST_URL = 'https://www.suse.com/security/cve/index.html'
SUSE_CVE_URL_TEMPLATE = 'https://www.suse.com/security/cve/{cve}.html'


class Cache:
    """
    Holds the session instance
    """
    _INSTANCE = None

    @staticmethod
    def instance():
        if Cache._INSTANCE is None:
            Cache._INSTANCE = CachedSession(
                str(Path(settings.cache.path) / 'scf.sqlite'),
                expire_after=timedelta(days=settings.cache.expiration_days),
                urls_expire_after={f"*/{cve}.html": -1 for cve in settings.cache.expiration_exceptions},
                backend='sqlite',
                stale_if_error=True)
        return Cache._INSTANCE


def url_to_soup(url: str, timeout: int = 30, use_cache: bool = True):
    """
    Fetches the html and returns a beautifulsoup instance
    """

    cache = Cache.instance()

    if not use_cache:
        cache.cache.delete_url(url)

    user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0'}

    res = cache.get(url,
                    headers=user_agent,
                    timeout=timeout,
                    verify=settings.connection.ssl_verify)

    res.raise_for_status()

    return BeautifulSoup(res.text, 'html.parser')


def list_cve_by_year(timeout: int = 30, use_cache: bool = False) -> Dict[str, list]:
    """
    Fetches all cves grouped by year

    Returns a dict with the years as keys and the cves as values in a list
    """
    soup = url_to_soup(SUSE_CVE_LIST_URL, timeout=timeout, use_cache=use_cache)
    current_year = ''
    cve_list: DefaultDict[str, list] = defaultdict(list)
    for tag in soup.select('div#mainbody > h3, div#mainbody > a'):
        if tag.name == "h3":
            current_year = tag.text.split()[0]
        elif tag.name == "a":
            cve_list[current_year].append(tag.text)
        else:
            raise ValueError(f"Unexpected html tag found (tag: {tag.name})")
    return cve_list


def get_all_cve(timeout: int = 30, use_cache: bool = False) -> list:
    """
    Fetches all cves
    """
    by_year = list_cve_by_year(timeout=timeout, use_cache=use_cache)
    return sorted([cve for ylist in by_year.values() for cve in ylist], key=numeric, reverse=True)


def prefetch_cve(cve: str, timeout: int = 30) -> str:
    """
    Prefetches the cve and save the html into cache
    """
    url = SUSE_CVE_URL_TEMPLATE.format(cve=cve)
    url_to_soup(url, timeout=timeout, use_cache=True)
    return cve


def get_cve_details(cve: str, timeout: int = 30, use_cache: bool = True) -> CVE:
    """
    Fetches the details of a cve

    Returns a CVE object
    """
    url = SUSE_CVE_URL_TEMPLATE.format(cve=cve)
    soup = url_to_soup(url, timeout=timeout, use_cache=use_cache)

    data = {'name': cve, 'url': url}

    # parse description
    description_header_tag = soup.select_one('div#mainbody > h4:-soup-contains("Description")')
    data['description'] = description_header_tag.next_sibling.text.strip('\n')

    # parse overall state
    match = re.search(r"Overall state of this security issue: (\w+)", soup.text)
    if match:
        data['overall_state'] = OverallState[match.groups()[0].upper().replace(' ', '_')]

    # parse suse rating
    match = re.search(r"This issue is currently rated as having (\w+) severity", soup.text)
    if match:
        data['simplified_rating'] = SimplifiedRating[match.groups()[0].upper()]

    # parse cvss
    cvss_table_caption_tag = soup.select_one('div#mainbody > table > caption > a:-soup-contains("CVSS v3 Scores")')
    if cvss_table_caption_tag:
        cvss_table = cvss_table_caption_tag.find_parent('table')

        # parse the cvss data
        base_score = float(list(cvss_table.select_one('td:-soup-contains("Base Score")').parent.children)[-1].text)
        vector = list(cvss_table.select_one('td:-soup-contains("Vector")').parent.children)[-1].text
        version = list(cvss_table.select_one('td:-soup-contains("CVSSv3 Version")').parent.children)[-1].text

        data['cvss'] = CVSS(score=base_score, vector=CVSSVector.from_string(vector), version=version)

    # parse products
    products_table_header_tag = soup.select_one('div#mainbody > table th:-soup-contains("Source package")')
    if products_table_header_tag:
        products_table = products_table_header_tag.find_parent('table')
        products = []

        for row in products_table.select('tr')[1:]:
            product, source, status = [i.text for i in row.select('td')]
            for single_product in product.split('\n'):
                products.append(Product(name=single_product, package=source, state=State[status.upper().replace(' ', '_').replace('\'', '_')]))
        data['affected_products'] = products

    return CVE(**data)
