"""
Small api server
"""
import uvicorn
from fastapi import FastAPI
from .models import CVE
from .suse import get_all_cve, get_cve_details, list_cve_by_year, Cache


app = FastAPI(docs_url='/')


@app.post('/cache/clear', summary='Clear the cache', tags=['Cache'])
async def cache_clear():
    """
    Clear the cache
    """
    Cache.instance().cache.clear()
    return {'result': 'success'}, 200


@app.post('/cache/clean', summary='Clean the cache (remove expired entries)', tags=['Cache'])
async def cache_clean():
    """
    Clean the cache
    """
    Cache.instance().remove_expired_responses()
    return {'result': 'success'}, 200


@app.get('/cve', summary='Fetch all known CVEs', tags=['CVE'])
async def cve(use_cache: bool = False):
    """
    Returns a list with all cves
    """
    return get_all_cve(use_cache=use_cache)


@app.get('/cve/year', summary='Fetch all known CVEs grouped by year', tags=['CVE'])
async def cve_by_years(use_cache: bool = False):
    """
    Returns a list with all cves grouped by year
    """
    return list_cve_by_year(use_cache=use_cache)


@app.get('/cve/year/{year}', summary='Fetch all known CVEs for a specific year', tags=['CVE'])
async def cve_by_year(year: str, use_cache: bool = False):
    """
    Returns a list with all cves in the given year
    """
    year_cves = list_cve_by_year(use_cache=use_cache)
    if year in year_cves:
        return year_cves[year]
    return []


@app.get('/cve/{cve_id}', summary='Fetch details for a specific CVE', tags=['CVE'], response_model=CVE)
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
