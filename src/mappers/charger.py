"""Blue Smart IP22 / IP65 / IP67, Phoenix Smart -> com.victronenergy.charger.ble_<mac>.

Paths from the "AC chargers" section of the Venus OS D-Bus documentation:
  /NrOfOutputs        actual number of outputs
  /Dc/n/Voltage       V DC, output n (0 to /NrOfOutputs - 1)
  /Dc/n/Current       A DC
  /State              0=Off 2=Fault 3=Bulk 4=Absorption 5=Float 6=Storage 7=Equalize (manual)
                      11=Power supply mode 246=Repeated absorption 247=Auto equalize/Recondition
                      248=BatterySafe (raw code from the device, passed through as is)
  /ErrorCode          charger error code
  /Ac/In/L1/I         A AC: only when the model reports it (the Blue Smart IP65 does not)
Not published:
  /Mode, /Relay/0/State   control paths: this service is read only;
  /Dc/0/Temperature       documented as the BATTERY temperature, while victron_ble describes the
                          Instant Readout field as the charger's own temperature: not mixed up;
  /Ac/In/L1/P, /Ac/In/CurrentLimit, /Alarms/*   not carried by Instant Readout.
"""

from .base import Mapper

COMMON_PATHS = (
    ('/State', 'state', None, None),
    ('/ErrorCode', 'error', None, None),
)
AC_CURRENT_PATH = ('/Ac/In/L1/I', 'ac_current', 'A', '%.1f')


def nr_outputs(product_name, values):
    """3 for the "(3)" models; otherwise the highest output reporting a voltage, at least 1."""
    if '(3)' in (product_name or ''):
        return 3
    n = 1
    for i in (2, 3):
        if values.get('output_voltage%d' % i) is not None:
            n = i
    return n


class ChargerMapper(Mapper):
    SERVICE_CLASS = 'charger'

    def __init__(self, *args, **kwargs):
        Mapper.__init__(self, *args, **kwargs)
        self.outputs = nr_outputs(self.product_name, self.first_values)
        self.has_ac_current = self.first_values.get('ac_current') is not None

    def static_paths(self):
        return {'/NrOfOutputs': self.outputs}

    def paths(self):
        out = []
        for i in range(self.outputs):
            out.append(('/Dc/%d/Voltage' % i, 'output_voltage%d' % (i + 1), 'V', '%.2f'))
            out.append(('/Dc/%d/Current' % i, 'output_current%d' % (i + 1), 'A', '%.1f'))
        out.extend(COMMON_PATHS)
        if self.has_ac_current:
            out.append(AC_CURRENT_PATH)
        return tuple(out)
