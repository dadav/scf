import os
import json
import re
from random import random
from time import sleep
from multiprocessing import Pool
from typing import Optional, cast, Dict, List, Union
from datetime import datetime
from pathlib import Path
from subprocess import call, Popen, DEVNULL

import typer
import toml
from scf import __version__
from scf.server import run as server_start
from scf.suse import get_cve_details, list_cve_by_year, get_all_cve, prefetch_cve
from rich import print
from rich.progress import Progress
from rich.tree import Tree
from rich.live import Live
from rich.table import Table
from scf.suse import Cache
from scf.utils import find_by_path, file_size, numeric
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
        raise typer.Exit(1)
    os.makedirs(target.parent, exist_ok=True)

    with open(Path(__file__).parent / 'settings.toml', 'rt', encoding='utf-8') as default_config,\
            open(target, 'wt', encoding='utf-8') as target_config:
        target_config.write(default_config.read())


@config_cmd.command("dump")
def config_cmd_dump():
    """
    Dumps the current config
    """
    typer.echo(toml.dumps(settings.as_dict()))


@config_cmd.command("edit")
def config_cmd_edit():
    """
    Edit the current config
    """
    config = Path.home() / '.config' / 'scf' / 'settings.toml'
    if not config.exists():
        config_cmd_init()
    editor = os.environ.get('EDITOR', 'vim')
    raise typer.Exit(call([editor, config]))


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
        cache = cast(SQLiteCache, Cache.instance().cache)
        path = Path(cache.db_path)
        size = file_size(path)
        all_entries = cache.response_count()
        not_expired = cache.response_count(check_expiry=True)
        expired = all_entries - not_expired

    typer.echo(f'Location: {path}')
    typer.echo(f'Size: {size}')
    typer.echo(f'Total entries: {all_entries}')
    if all_entries > 0:
        typer.echo(f'Expired entries: {expired} ({100/all_entries*expired:.2f}%)')


@cache_cmd.command("populate")
def cache_cmd_populate(
        cve_filter: str = typer.Option(f'CVE-{datetime.now().year}-.*',
                                       '--filter', help="Regex to apply on the CVEs to fetch."),
        workers: int = typer.Option(1, '-w', '--workers', help='The number of workers that should be started'),) -> None:
    """
    Prefetch all the cve data
    """

    re_filter = re.compile(cve_filter)
    cve_list = list(filter(re_filter.match, get_all_cve(use_cache=False)))

    with Progress(transient=True) as progress:
        task = progress.add_task('Populating cache...', total=len(cve_list))

        with Pool(processes=workers) as pool:
            for cve in pool.imap_unordered(prefetch_cve, cve_list):
                progress.update(task, description=f'Populating cache...{cve}')
                progress.advance(task)
                sleep(random())


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


@cve_cmd.command("watch")
def cve_cmd_watch(
        command: str = typer.Option(None, '-c', '--command', help='Run this command if a new CVE is found'),
        test: bool = typer.Option(False, '-t', '--test', help='Test the command and exit'),
        interval: int = typer.Option(30, '-i', '--interval', help='Set the refresh interval'),) -> None:
    """
    Show the latest CVE as they get published
    """
    if test and not command:
        typer.echo('Give me a command.', err=True)
        raise typer.Exit(1)
    elif test:
        rc = call([command], shell=True, stdout=DEVNULL)
        typer.echo(f'Executed command. RC = {rc}')
        raise typer.Exit(0)

    table = Table()
    table.add_column('Time')
    table.add_column('CVE')
    table.add_column('Rating')
    table.add_column('Score')
    table.add_column('Overall state')

    last_cve = None
    first = True

    with Live(table, auto_refresh=False) as live:
        while True:
            try:
                all_cve = get_all_cve()
                new_cve = []

                if last_cve is None:
                    last_cve = all_cve[0]
                    new_cve.append(last_cve)
                else:
                    while all_cve[0] != last_cve:
                        new_cve.append(all_cve[0])
                        all_cve.pop()

                for cve in reversed(new_cve):
                    cve_data = get_cve_details(cve)
                    rating = cve_data.simplified_rating or 'Unknown'
                    overall = cve_data.overall_state or 'Unknown'

                    if cve_data.cvss is not None and cve_data.cvss.score is not None:
                        score = str(cve_data.cvss.score)
                    else:
                        score = 'Unknown'

                    table.add_row(datetime.now().strftime('%Y/%m/%d %H:%M:%S'), cve, rating, score, overall)
                    live.update(table, refresh=True)
                    if command and not first:
                        Popen([command], shell=True, stdout=DEVNULL)
                sleep(interval)
                first = False
            except KeyboardInterrupt:
                break


@cve_cmd.command("list")
def cve_cmd_list(
        year: bool = typer.Option(False, '-y', '--year', help='List cve grouped by year.'),
        use_cache: bool = typer.Option(False, '--cache', help='Enables the cache.'),
        use_json: bool = typer.Option(False, '--json', help='Print the result as json.'),) -> None:
    """
    Fetch the known cve for a given year or all.
    """
    cves: Union[Dict, List] = []

    if year:
        cves = list_cve_by_year(use_cache=use_cache)
    else:
        cves = get_all_cve(use_cache=use_cache)

    if use_json:
        typer.echo(json.dumps(cves))
    else:
        tree = Tree('CVE')
        if isinstance(cves, dict):
            for cve_year, cve_list in cves.items():
                t_y = tree.add(cve_year)
                for cve in sorted(cve_list, key=numeric, reverse=True):
                    t_y.add(cve)
        else:
            for cve in cves:
                tree.add(cve)
        print(tree)


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
