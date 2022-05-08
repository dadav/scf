"""
Contains the code to fetch the informations from suse.com
"""
import re
from collections import defaultdict
import requests as r
from bs4 import BeautifulSoup
from models import CVE, SimplifiedRating, CVSS, CVSSVector, State, Product


def url_to_soup(url: str, timeout: int = 30):
    """
    Fetches the html and returns a beautifulsoup instance
    """
    res = r.get(url, timeout=timeout)
    res.raise_for_status()
    return BeautifulSoup(res.text, 'html.parser')


def cves_by_year(timeout: int = 30) -> dict[str, list]:
    """
    Fetches all cves grouped by year

    Returns a dict with the years as keys and the cves as values in a list
    """
    soup = url_to_soup('https://www.suse.com/security/cve/index.html', timeout=timeout)
    current_year = None
    cve_list = defaultdict(list)
    for tag in soup.select('div#mainbody > h3, div#mainbody > a'):
        if tag.name == "h3":
            current_year = tag.text.split()[0]
        elif tag.name == "a":
            cve_list[current_year].append(tag.text)
        else:
            raise ValueError(f"Unexpected html tag found (tag: {tag.name})")
    return cve_list


def cve_details(cve: str, timeout: int = 30) -> CVE:
    """
    Fetches the details of a cve

    Returns a CVE object
    """
    url = f'https://www.suse.com/security/cve/{cve}.html'
    soup = url_to_soup(url, timeout=timeout)
    data = {'name': cve, 'url': url}

    # parse description
    description_header_tag = soup.select_one('div#mainbody > h4:-soup-contains("Description")')
    data['description'] = description_header_tag.next_sibling.text.strip('\n')

    # parse suse rating
    if match := re.search(r"This issue is currently rated as having (\w+) severity", soup.text):
        data['simplified_rating'] = SimplifiedRating[match.groups()[0].upper()]

    # parse cvss
    cvss_table_caption_tag = soup.select_one('div#mainbody > table > caption > a:-soup-contains("CVSS v3 Scores")')
    cvss_table = cvss_table_caption_tag.find_parent('table')

    base_score = float(list(cvss_table.select_one('td:-soup-contains("Base Score")').parent.children)[-1].text)
    vector = list(cvss_table.select_one('td:-soup-contains("Vector")').parent.children)[-1].text
    version = list(cvss_table.select_one('td:-soup-contains("CVSSv3 Version")').parent.children)[-1].text

    data['cvss'] = CVSS(score=base_score, vector=CVSSVector.from_string(vector), version=version)

    # parse products
    products_table_header_tag = soup.select_one('div#mainbody > table th:-soup-contains("Source package")')
    products_table = products_table_header_tag.find_parent('table')
    products = list()

    for row in products_table.select('tr')[1:]:
        product, source, status = [i.text for i in row.select('td')]
        products.append(Product(name=product, package=source, state=State[status.upper().replace(' ', '_')]))
    data['affected_products'] = products

    return CVE(**data)
