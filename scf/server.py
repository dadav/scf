"""
Small api server
"""
import uvicorn
from fastapi import FastAPI
from .models import CVE
from .suse import get_all_cve, get_cve_details, list_cve_by_year


app = FastAPI(docs_url='/')


@app.get('/cve')
async def cve(use_cache: bool = False):
    """
    Returns a list with all cves
    """
    return get_all_cve(use_cache=use_cache)


@app.get('/cve/year')
async def cve_by_years(use_cache: bool = False):
    """
    Returns a list with all cves grouped by year
    """
    return list_cve_by_year(use_cache=use_cache)


@app.get('/cve/year/{year}')
async def cve_by_year(year: str, use_cache: bool = False):
    """
    Returns a list with all cves in the given year
    """
    year_cves = list_cve_by_year(use_cache=use_cache)
    if year in year_cves:
        return year_cves[year]
    return []


@app.get('/cve/{cve_id}', response_model=CVE)
async def cve_by_id(cve_id: str, use_cache: bool = True):
    """
    Returns the details for a given cve
    """
    return get_cve_details(cve_id, use_cache=use_cache)


def run(host: str = '0.0.0.0',
        port: int = 8000,
        workers: int = 1) -> None:
    """
    Starts the uvicorn server
    """
    uvicorn.run("scf.server:app", host=host, port=port, debug=False, workers=workers)
