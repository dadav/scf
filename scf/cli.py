import os
import json
import re
from multiprocessing import Pool
from typing import Optional, cast
from datetime import datetime
from pathlib import Path

import typer
import toml
from scf import __version__
from scf.server import run as server_start
from scf.suse import get_cve_details, list_cve_by_year, get_all_cve, prefetch_cve
from rich import print
from rich.progress import Progress
from rich.tree import Tree
from scf.suse import Cache
from scf.utils import find_by_path, file_size
from requests_cache.backends.sqlite import SQLiteCache
from scf.config import settings


app = typer.Typer(context_settings={'help_option_names': ['-h', '--help']})
cache_cmd = typer.Typer(context_settings={'help_option_names': ['-h', '--help']}, add_completion=False)
cve_cmd = typer.Typer(context_settings={'help_option_names': ['-h', '--help']}, add_completion=False)
server_cmd = typer.Typer(context_settings={'help_option_names': ['-h', '--help']}, add_completion=False)
config_cmd = typer.Typer(context_settings={'help_option_names': ['-h', '--help']}, add_completion=False)

app.add_typer(cache_cmd, name='cache')
app.add_typer(cve_cmd, name='cve')
app.add_typer(server_cmd, name='server')
app.add_typer(config_cmd, name='config')


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"v{__version__}")
        raise typer.Exit()


@config_cmd.command("init")
def config_cmd_init(
        overwrite: bool = typer.Option(False, '--overwrite', help='Overwrite if already exists.'),) -> None:
    """
    Creates the default config in the home directory
    """
    target = Path.home() / '.config' / 'scf' / 'settings.toml'
    if target.exists() and not overwrite:
        typer.echo(f'Config already exists ({target})', err=True)
        typer.Exit(1)
    os.makedirs(target.parent, exist_ok=True)

    with open(Path(__file__).parent / 'settings.toml', 'rt') as default_config, open(target, 'wt') as target_config:
        target_config.write(default_config.read())


@config_cmd.command("dump")
def config_cmd_dump():
    """
    Dumps the current config
    """
    typer.echo(toml.dumps(settings.as_dict()))


@server_cmd.command("run")
def server_cmd_run(
        host: str = typer.Option('0.0.0.0', '--host', help='The host ip to bind the socket to.'),
        port: int = typer.Option(8000, '--port', help='The port to which the socket should listen to.'),
        workers: int = typer.Option(os.cpu_count(), '-w', '--workers', help='The number of workers that should be started'),) -> None:
    """
    Starts the uvicorn server
    """
    server_start(host=host, port=port, workers=workers)


@cache_cmd.command("clean")
def cache_cmd_clean() -> None:
    """
    Remove expired cache entries
    """
    Cache.instance().remove_expired_responses()


@cache_cmd.command("clear")
def cache_cmd_clear() -> None:
    """
    Clear the whole cache
    """
    Cache.instance().cache.clear()


@cache_cmd.command("stats")
def cache_cmd_stats() -> None:
    """
    Get some stats about the cache
    """
    with Progress(transient=True) as progress:
        progress.add_task('Collecting data...', total=None)
        c = cast(SQLiteCache, Cache.instance().cache)
        path = Path(c.db_path)
        size = file_size(path)
        all_entries = c.response_count()
        not_expired = c.response_count(check_expiry=True)
        expired = all_entries - not_expired

    typer.echo(f'Location: {path}')
    typer.echo(f'Size: {size}')
    typer.echo(f'Total entries: {all_entries}')
    typer.echo(f'Expired entries: {expired} ({100/all_entries*expired:.2f}%)')


@cache_cmd.command("populate")
def cache_cmd_populate(
        cve_filter: str = typer.Option(f'CVE-{datetime.now().year}-.*', '--filter', help="Regex to apply on the CVEs to fetch.")) -> None:
    """
    Prefetch all the cve data
    """

    re_filter = re.compile(cve_filter)
    cve_list = list(filter(re_filter.match, get_all_cve(use_cache=False)))

    with Progress(transient=True) as progress:
        task = progress.add_task('Populating cache...', total=len(cve_list))

        with Pool(processes=os.cpu_count()) as pool:
            for cve in pool.imap_unordered(prefetch_cve, cve_list):
                progress.update(task, description=f'Populating cache...{cve}')
                progress.advance(task)


@cve_cmd.command("details")
def cve_cmd_details(
        name: str = typer.Argument(None, help='The cve identifier to lookup.'),
        disable_cache: bool = typer.Option(False, '--no-cache', help='Disable the cache.'),
        field: str = typer.Option(None, '--field', help='Only print the given field (e.g. `cvss.score`)'),
        use_json: bool = typer.Option(False, '--json', help='Print the result as json.'),) -> None:
    """
    Fetch the details of a given cve
    """
    details = get_cve_details(name, use_cache=not disable_cache)
    if field is not None:
        selected = find_by_path(field, details.asdict())
        if use_json:
            typer.echo(json.dumps(selected))
        typer.echo(selected)
    elif use_json:
        typer.echo(details.json())
    else:
        print(details.tree())


@cve_cmd.command("list")
def cve_cmd_list(
        year: bool = typer.Option(False, '-y', '--year', help='List cve grouped by year.'),
        use_cache: bool = typer.Option(False, '--cache', help='Enables the cache.'),
        use_json: bool = typer.Option(False, '--json', help='Print the result as json.'),) -> None:
    """
    Fetch the known cve for a given year or all.
    """

    if year:
        cves = list_cve_by_year(use_cache=use_cache)
    else:
        cves = get_all_cve(use_cache=use_cache)

    if use_json:
        typer.echo(json.dumps(cves))
    else:
        t = Tree('CVE')
        if isinstance(cves, dict):
            for cve_year, cve_list in cves.items():
                t_y = t.add(cve_year)
                for cve in cve_list:
                    t_y.add(cve)
        else:
            for cve in cves:
                t.add(cve)
        print(t)


@app.callback()
def main(
    _: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=_version_callback,
        is_eager=True,)) -> None:
    """
    scf fetches informations about CVEs from suse.com.
    """
    return
