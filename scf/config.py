"""
Contains config specific stuff
"""

from pathlib import Path
from dynaconf import Dynaconf

settings = Dynaconf(
    envvar_prefix="SCF",
    settings_files=['settings.toml',
                    f'{Path.home() / ".config" / "scf" / "settings.toml"}',
                    f'{Path(__file__).parent / "settings.toml"}'],
)
