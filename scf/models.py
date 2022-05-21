"""
Contain models used by this package
"""
import json
from typing import List, Optional
from enum import Enum
from pydantic import BaseModel
from rich.tree import Tree
from fastapi.encoders import jsonable_encoder


class OverallState(str, Enum):
    """
    Overall state by Suse: https://www.suse.com/c/cve-pages-self-help-security-issues-suse-linux-enterprise/
    """
    RESOLVED = 'RESOLVED'
    DOES = 'DOES_NOT_AFFECT_SUSE'
    PENDING = 'PENDING'
    RUNNING = 'RUNNING'
    ANALYSIS = 'ANALYSIS'
    NEW = 'NEW'
    POSTBONED = 'POSTBONED'
    IGNORE = 'IGNORE'

    def pretty(self):
        """
        Returns the colorized enum value
        """
        color = {
            'RESOLVED': 'green',
            'DOES_NOT_AFFECT_SUSE': 'green',
            'PENDING': 'yellow',
            'RUNNING': 'slate_blue1',
            'ANALYSIS': 'slate_blue1',
            'NEW': 'slate_blue1',
            'POSTBONED': 'slate_blue1',
            'IGNORE': 'green',
        }[self.name]
        return f'[{color}]{self.value}[/{color}]'


class SimplifiedRating(str, Enum):
    """
    Simplified Rating by Suse: https://www.suse.com/support/security/rating/
    """
    LOW = 'LOW'
    MODERATE = 'MODERATE'
    IMPORTANT = 'IMPORTANT'
    CRITICAL = 'CRITICAL'

    def pretty(self):
        """
        Returns the colorized enum value
        """
        color = {
            'LOW': 'green',
            'MODERATE': 'yellow',
            'IMPORTANT': 'orange_red1',
            'CRITICAL': 'red1',
        }[self.name]
        return f'[{color}]{self.value}[/{color}]'


class State(str, Enum):
    """
    Represents how the state of an affected package can be described
    """
    IN_PROGRESS = 'IN_PROGRESS'
    WON_T_FIX = 'WILL_NOT_FIX'
    UNSUPPORTED = 'UNSUPPORTED'
    RELEASED = 'RELEASED'
    AFFECTED = 'AFFECTED'
    NOT_AFFECTED = 'NOT_AFFECTED'
    ALREADY_FIXED = 'ALREADY_FIXED'
    ANALYSIS = 'ANALYSIS'
    ASK_MAINTAINER = 'ASK_MAINTAINER'

    def pretty(self):
        """
        Returns the colorized enum value
        """
        color = {
            'NOT_AFFECTED': 'green',
            'ALREADY_FIXED': 'green',
            'RELEASED': 'green',
            'UNSUPPORTED': 'orange_red1',
            'IN_PROGRESS': 'slate_blue1',
            'AFFECTED': 'red1',
            'ANALYSIS': 'slate_blue1',
            'WON_T_FIX': 'yellow',
            'ASK_MAINTAINER': 'yellow',
        }[self.name]
        return f'[{color}]{self.value}[/{color}]'


class Product(BaseModel):  # pylint: disable=too-few-public-methods
    """
    Contains information about a package that may or maybe not is affected by a given cve
    """
    name: str
    package: str
    state: State

    def tree(self):
        """
        Creates a pretty rich tree object
        """
        t = Tree(self.name)
        p = t.add('Package')
        p.add(self.package)
        s = t.add('State')
        s.add(self.state.pretty())
        return t


class CVSSVector(BaseModel):  # pylint: disable=too-few-public-methods
    """
    Contains the parsed vector information
    """
    _STR2VAR = {
        'av': {
            'name': 'access_vector',
            'values': {
                'N': 'Network',
                'A': 'Adjacent',
                'L': 'Local',
                'P': 'Physical'
            }
        },
        'ac': {
            'name': 'access_complexity',
            'values': {
                'L': 'Low',
                'H': 'High',
            },
        },
        'pr': {
            'name': 'privileges_required',
            'values': {
                'N': 'None',
                'L': 'Low',
                'H': 'High',
            },
        },
        'ui': {
            'name': 'user_interaction',
            'values': {
                'N': 'None',
                'R': 'Required',
            },
        },
        's': {
            'name': 'scope',
            'values': {
                'U': 'Unchanged',
                'C': 'Changed',
            },
        },
        'c': {
            'name': 'confidentiality_impact',
            'values': {
                'H': 'High',
                'L': 'Low',
                'N': 'None',
            },
        },
        'i': {
            'name': 'integrity_impact',
            'values': {
                'H': 'High',
                'L': 'Low',
                'N': 'None',
            },
        },
        'a': {
            'name': 'availability_impact',
            'values': {
                'H': 'High',
                'L': 'Low',
                'N': 'None',
            },
        },
        'cvss': {'name': 'version', 'values': {}},
    }
    raw: str
    access_vector: str
    access_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    version: str

    def tree(self):
        """
        Creates a pretty rich tree object
        """
        t = Tree('[light_slate_blue]Vector')

        t_r = t.add('[sky_blue2]Raw')
        t_r.add(self.raw)

        t_av = t.add('[sky_blue2]Access Vector')
        t_av.add(self.access_vector)

        t_ac = t.add('[sky_blue2]Access Complexity')
        t_ac.add(self.access_complexity)

        t_pr = t.add('[sky_blue2]Privileges Required')
        t_pr.add(self.privileges_required)

        t_ui = t.add('[sky_blue2]User Interaction')
        t_ui.add(self.user_interaction)

        t_s = t.add('[sky_blue2]Scope')
        t_s.add(self.scope)

        t_ci = t.add('[sky_blue2]Confidentiality Impact')
        t_ci.add(self.confidentiality_impact)

        t_ii = t.add('[sky_blue2]Integrity Impact')
        t_ii.add(self.integrity_impact)

        t_ai = t.add('[sky_blue2]Availability Impact')
        t_ai.add(self.availability_impact)

        t_v = t.add('[sky_blue2]Version')
        t_v.add(self.version)

        return t

    @staticmethod
    def from_string(cvss_str):
        """
        Parses a raw cvss vector string
        """
        data = {'raw': cvss_str}
        for name, value in [kv.split(':') for kv in cvss_str.split('/')]:
            lookup = CVSSVector._STR2VAR[name.lower()]
            data[lookup['name']] = lookup['values'].get(value, value)
        return CVSSVector(**data)


class CVSS(BaseModel):  # pylint: disable=too-few-public-methods
    """
    Contains the fetched cvss information
    """
    score: float
    vector: CVSSVector
    version: str

    def tree(self):
        """
        Creates a pretty rich tree object
        """
        t = Tree('[slate_blue1]CVSS')

        t_s = t.add('[light_slate_blue]Score')
        t_s.add(str(self.score))

        t.add(self.vector.tree())

        t_v = t.add('[light_slate_blue]Version')
        t_v.add(self.version)

        return t


class CVE(BaseModel):  # pylint: disable=too-few-public-methods
    """
    Holds all the information about the cve
    """
    name: str
    description: str
    url: str
    overall_state: Optional[OverallState]
    cvss: Optional[CVSS]
    simplified_rating: Optional[SimplifiedRating]
    affected_products: Optional[List[Product]]

    def asdict(self):
        """
        Returns the data as dict
        """
        return dict(jsonable_encoder(self))

    def json(self):
        """
        Returns the data as json
        """
        return json.dumps(self.asdict())

    def tree(self):
        """
        Creates a pretty rich tree object
        """
        t = Tree(f'[sea_green3]{self.name}')
        t_d = t.add('[slate_blue1]Description')
        t_d.add(self.description)

        t_u = t.add('[slate_blue1]Url')
        t_u.add(self.url)

        if self.overall_state:
            t_os = t.add('[slate_blue1]Overall state')
            t_os.add(self.overall_state.pretty())

        if self.cvss:
            t.add(self.cvss.tree())

        if self.simplified_rating:
            t_s = t.add('[slate_blue1]Simplified Rating')
            t_s.add(self.simplified_rating.pretty())

        if self.affected_products:
            t_p = t.add('[slate_blue1]Products')
            for p in self.affected_products:
                t_p.add(p.tree())

        return t
