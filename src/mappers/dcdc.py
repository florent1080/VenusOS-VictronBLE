"""Orion-Tr Smart / Orion Smart -> com.victronenergy.dcdc.ble_<mac>.

Paths from the "DCDC converters" section of the Venus OS D-Bus documentation:
  /Dc/0/Voltage     output voltage
  /Dc/In/V          input voltage (starter battery side)
  /State            0=Off 2=Fault 3=Bulk 4=Absorption 5=Float 6=Storage 7=Equalize 11=Psu
                    (raw VE.Direct code from the device, other values passed through as is)
  /ErrorCode        VE.Direct error code ("see solar charger section")
  /DeviceOffReason  VE.Direct off-reason bit mask ("see solar charger section")
Not published: /Dc/0/Current, /Dc/In/I and the powers (the Orion-Tr does not measure
current, the record carries none), /Mode (control path: this service is read only).
"""

from .base import Mapper


class DcdcMapper(Mapper):
    SERVICE_CLASS = 'dcdc'
    PATHS = (
        ('/Dc/0/Voltage', 'output_voltage', 'V', '%.2f'),
        ('/Dc/In/V', 'input_voltage', 'V', '%.2f'),
        ('/State', 'state', None, None),
        ('/ErrorCode', 'error', None, None),
        ('/DeviceOffReason', 'off_reason', None, '0x%X'),
    )
