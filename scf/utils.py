"""
Contains helper functions
"""
import os
import operator
from typing import Tuple
from pathlib import Path
from functools import reduce


def find_by_path(element: str, json: dict):
    """
    Finds a value by a gived key-path
    src: https://stackoverflow.com/a/31033676
    """
    return reduce(operator.getitem, element.split('.'), json)


def file_size(path: Path, human_readable: bool = True) -> str:
    """
    Gets the filesize and optionally formats it
    """
    size_in_bytes = os.path.getsize(path)

    if not human_readable:
        return str(size_in_bytes)

    # https://gist.github.com/cbwar/d2dfbc19b140bd599daccbe0fe925597
    for unit in ['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(size_in_bytes) < 1024.0:
            return f'{size_in_bytes:3.1f}{unit}'
        size_in_bytes /= 1024.0

    return f'{size_in_bytes:3.1f}Yi'


def numeric(cve: str) -> Tuple[int, int]:
    """
    Returns a numeric cve number for sorting
    """
    year, num = cve[4:].split('-')
    return (int(year), int(num))
