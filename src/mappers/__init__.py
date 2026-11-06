"""Readings -> read-only Venus OS D-Bus services, one mapper per device type.

Adding a type: a Mapper subclass with SERVICE_CLASS and PATHS (see dcdc.py), registered here
under the same name as in parsers.DEVICE_TYPES.
"""

from .base import CONNECTION, Mapper, mac_id, velib
from .charger import ChargerMapper
from .dcdc import DcdcMapper

__all__ = ['CONNECTION', 'Mapper', 'mac_id', 'velib', 'ChargerMapper', 'DcdcMapper', 'MAPPERS']

MAPPERS = {
    'dcdc': DcdcMapper,
    'charger': ChargerMapper,
}
