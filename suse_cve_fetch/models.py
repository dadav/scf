"""
Contain models used by this package
"""
from typing import List, Optional
from enum import Enum, auto
from pydantic import BaseModel


class SimplifiedRating(Enum):
    """
    Simplified Rating by Suse: https://www.suse.com/support/security/rating/
    """
    LOW = auto()
    MODERATE = auto()
    IMPORTANT = auto()
    CRITICAL = auto()


class State(Enum):
    """
    Represents how the state of an affected package can be described
    """
    IN_PROGRESS = auto()
    UNSUPPORTED = auto()
    RELEASED = auto()
    AFFECTED = auto()
    NOT_AFFECTED = auto()
    ALREADY_FIXED = auto()


class Product(BaseModel):  # pylint: disable=too-few-public-methods
    """
    Contains information about a package that may or maybe not is affected by a given cve
    """
    name: str
    package: str
    state: State


class CVSSVector(BaseModel):  # pylint: disable=too-few-public-methods
    """
    Contains the parsed vector information
    """
    _STR2VAR = {
        'av': 'access_vector',
        'ac': 'access_complexity',
        'pr': 'privileges_required',
        'ui': 'user_interaction',
        's': 'scope',
        'c': 'confidentiality_impact',
        'i': 'integrity_impact',
        'a': 'availability_impact',
        'cvss': 'version',
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

    @staticmethod
    def from_string(cvss_str):
        """
        Parses a raw cvss vector string
        """
        data = {'raw': cvss_str}
        for name, value in [kv.split(':') for kv in cvss_str.split('/')]:
            data[CVSSVector._STR2VAR[name.lower()]] = value
        return CVSSVector(**data)


class CVSS(BaseModel):  # pylint: disable=too-few-public-methods
    """
    Contains the fetched cvss information
    """
    score: float
    vector: CVSSVector
    version: float


class CVE(BaseModel):  # pylint: disable=too-few-public-methods
    """
    Holds all the information about the cve
    """
    name: str
    description: str
    url: str
    cvss: CVSS
    simplified_rating: Optional[SimplifiedRating]
    affected_products: Optional[List[Product]]
