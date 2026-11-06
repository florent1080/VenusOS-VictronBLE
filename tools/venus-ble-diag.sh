#!/bin/sh
# venus-ble-diag.sh - VenusOS-VictronBLE, etape 0 : diagnostic Bluetooth / Instant Readout
#
# A lancer en root sur le GX (Venus OS) :
#     sh /tmp/venus-ble-diag.sh                  # 30 s par phase de capture
#     sh /tmp/venus-ble-diag.sh -t 60            # 60 s par phase
#     sh /tmp/venus-ble-diag.sh --passive-only   # sans le test de decouverte BlueZ
#     sh /tmp/venus-ble-diag.sh --advmon         # 2e test : scan passif AdvertisementMonitor
#     sh /tmp/venus-ble-diag.sh --advmon --ble-sensors   # + capteurs Bluetooth de Venus
#     sh /tmp/venus-ble-diag.sh --sensors -t 600 # 3e test : capteurs Bluetooth de Venus seuls, 10 min
#
# Lecture seule : aucune connexion GATT, aucun appairage, aucun service arrete ni
# redemarre. Mode par defaut : la phase 8 demande a BlueZ une decouverte LE de
# quelques secondes (SetDiscoveryFilter + StartDiscovery), arretee a la fin.
# Mode --advmon : un AdvertisementMonitor BlueZ est enregistre pendant la mesure.
# Dans les deux cas, BlueZ arrete tout de lui-meme a la deconnexion du client D-Bus.
# Seul reglage touche : avec --ble-sensors, /Settings/Services/BleSensors passe a 1
# le temps des phases S1/S2 (comme l'interrupteur de l'interface), puis reprend sa
# valeur initiale, y compris en cas d'interruption.
#
# Sorties dans /tmp/venus-ble-diag/ (ou /tmp/venus-ble-diag2/ en mode --advmon ; option -o) :
#     diag.log              tout ce qui s'affiche a l'ecran
#     victron_adv.jsonl     trames Victron (0x02E1) capturees, une par ligne
#     discovery_dbus.jsonl  mises a jour ManufacturerData vues cote D-Bus (phase 8)
#     *.btsnoop             captures HCI brutes (relire avec : btmon -r fichier)
#     results/*.json        resultats structures (un fichier par mesure), lus par la synthese
#     diag_helper.py        partie Python de ce script (regeneree a chaque execution)

DUR=30
OUT=
MODE=diag
DO_DISCOVERY=1
DO_BLESENSORS=0
BTMON_PID=
HCIMON_PID=
SLEEP_PID=
BLE_RESTORE=

usage() {
    echo "usage : sh $0 [-t SECONDES] [-o REPERTOIRE] [--passive-only | --advmon [--ble-sensors]]"
    echo "  -t SECONDES      duree de chaque phase de capture (5 a 600, defaut 30)"
    echo "  -o REPERTOIRE    repertoire de sortie (defaut /tmp/venus-ble-diag, ou -diag2 avec --advmon)"
    echo "  --passive-only   ne pas lancer la decouverte BlueZ (phase 8)"
    echo "  --advmon         2e test : AdvertisementMonitor (scan passif BlueZ) au lieu du diagnostic"
    echo "  --ble-sensors    avec --advmon : active les capteurs Bluetooth de Venus le temps du test"
    echo "  --sensors        3e test : capteurs Bluetooth de Venus seuls pendant -t secondes (sans moniteur)"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -t) DUR="$2"; shift 2 ;;
        -o) OUT="$2"; shift 2 ;;
        --passive-only) DO_DISCOVERY=0; shift ;;
        --advmon) MODE=advmon; shift ;;
        --sensors) MODE=sensors; shift ;;
        --ble-sensors) DO_BLESENSORS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "option inconnue : $1"; usage; exit 2 ;;
    esac
done
if [ "$DO_BLESENSORS" = 1 ] && [ "$MODE" != advmon ]; then
    echo "--ble-sensors ne s'utilise qu'avec --advmon"; exit 2
fi
if [ -z "$OUT" ]; then
    case "$MODE" in
        advmon) OUT=/tmp/venus-ble-diag2 ;;
        sensors) OUT=/tmp/venus-ble-diag3 ;;
        *) OUT=/tmp/venus-ble-diag ;;
    esac
fi

case "$DUR" in
    ''|*[!0-9]*) echo "duree invalide : '$DUR'"; usage; exit 2 ;;
esac
if [ "$DUR" -lt 5 ] || [ "$DUR" -gt 600 ]; then
    echo "duree hors bornes (5 a 600 s) : $DUR"; exit 2
fi
if [ "$(id -u)" != "0" ]; then
    echo "a lancer en root (btmon a besoin du canal moniteur HCI)"; exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 introuvable"; exit 1
fi
mkdir -p "$OUT" || exit 1
rm -f "$OUT"/*.btsnoop "$OUT"/*.jsonl "$OUT"/results.json "$OUT"/results/*.json "$OUT"/btmon_*.txt \
    "$OUT"/hcimon_*.txt "$OUT"/services_*.txt

HELPER="$OUT/diag_helper.py"
export DIAG_OUT="$OUT"

# ---------------------------------------------------------------------------
# Partie Python : bibliotheque standard + dbus-python + GLib uniquement.
# ---------------------------------------------------------------------------
cat > "$HELPER" <<'PYEOF'
# Partie Python de venus-ble-diag.sh : regeneree a chaque execution, ne pas modifier ici.
# Bibliotheque standard + dbus-python + GLib (deja presents sur Venus OS) uniquement.
import glob
import hashlib
import importlib
import json
import os
import re
import struct
import sys
import time

OUT = os.environ.get('DIAG_OUT') or os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(OUT, 'results')
VELIB = '/opt/victronenergy/dbus-systemcalc-py/ext/velib_python'
BUSITEM = 'com.victronenergy.BusItem'
SETTINGS = 'com.victronenergy.settings'
VICTRON_CID = 0x02E1
BTSNOOP_EPOCH_1970 = 0x00DCDDB30F2F8000   # microsecondes entre l'an 0 et 1970

# NIST SP 800-38A, F.1.1 (ECB-AES128.Encrypt, bloc 1)
AES_KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
AES_PT = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
AES_CT = bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97')

# Octet 4 de la trame Instant Readout, d'apres victron_ble (a confirmer a l'etape 2)
RECORD_TYPES = {
    0x00: 'Test', 0x01: 'Solar charger', 0x02: 'Battery monitor', 0x03: 'Inverter',
    0x04: 'DC/DC converter', 0x05: 'SmartLithium', 0x06: 'Inverter RS', 0x07: 'GX device',
    0x08: 'AC charger', 0x09: 'Smart BatteryProtect', 0x0A: 'Lynx Smart BMS',
    0x0B: 'Multi RS', 0x0C: 'VE.Bus', 0x0D: 'DC energy meter', 0x0F: 'Orion XS',
}
LEGACY_EVT = {0: 'ADV_IND', 1: 'ADV_DIRECT_IND', 2: 'ADV_SCAN_IND', 3: 'ADV_NONCONN_IND', 4: 'SCAN_RSP'}
EXT_LEGACY_EVT = {0x13: 'ADV_IND', 0x15: 'ADV_DIRECT_IND', 0x12: 'ADV_SCAN_IND',
                  0x10: 'ADV_NONCONN_IND', 0x1B: 'SCAN_RSP', 0x1A: 'SCAN_RSP'}
SCAN_TYPE = {0: 'passif', 1: 'actif'}
DEV_CLASSES = ('solarcharger', 'battery', 'inverter', 'vebus', 'multi', 'dcdc', 'charger',
               'acsystem', 'alternator', 'dcsource', 'dcload', 'dcsystem', 'pvinverter')
DEV_PATHS = ('/DeviceInstance', '/ProductId', '/ProductName', '/CustomName', '/Serial',
             '/FirmwareVersion', '/Mgmt/Connection', '/Mgmt/ProcessName', '/Connected')


def err(e):
    return '%s: %s' % (type(e).__name__, e)


def load_res():
    """Fusionne les resultats : un fichier par cle, pour que deux processus lances en
    parallele (sonde HCI et moniteur) ne s'ecrasent jamais."""
    res = {}
    for path in sorted(glob.glob(os.path.join(RES, '*.json'))):
        try:
            with open(path) as f:
                res[os.path.basename(path)[:-5]] = json.load(f)
        except (OSError, ValueError):
            pass
    return res


def save_res(key, value):
    if not os.path.isdir(RES):
        os.makedirs(RES)
    path = os.path.join(RES, key + '.json')
    tmp = '%s.%d.tmp' % (path, os.getpid())
    with open(tmp, 'w') as f:
        json.dump(value, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def py(v):
    """Valeur dbus-python -> type Python simple (affichage, JSON)."""
    try:
        import dbus
        if isinstance(v, dbus.Boolean):
            return bool(v)
    except ImportError:
        pass
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return int(v)
    if isinstance(v, float):
        return float(v)
    if isinstance(v, str):
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    if isinstance(v, dict):
        return dict((py(k), py(x)) for k, x in v.items())
    if isinstance(v, (list, tuple)):
        if getattr(v, 'signature', None) == 'y':
            return bytes(bytearray(int(x) for x in v)).hex()
        return [py(x) for x in v]
    return str(v)


def show(v):
    if v is None:
        return 'absent'
    if v == []:
        return 'invalide ([])'
    return str(v)


def fmt_mac(b):
    return ':'.join('%02X' % x for x in reversed(b))


def u16(b, off):
    return b[off] | (b[off + 1] << 8)


def mfg_from_dbus(md):
    """ManufacturerData BlueZ (a{qv}) -> octets Victron, sans l'identifiant fabricant."""
    if not md:
        return None
    for k, v in md.items():
        if int(k) == VICTRON_CID:
            if isinstance(v, (bytes, bytearray)):
                return bytes(v)
            return bytes(bytearray(int(x) for x in v))
    return None


def victron_header(mfg):
    """En-tete en clair d'une trame Instant Readout, decoupe comme victron_ble."""
    if len(mfg) < 8 or mfg[0] != 0x10:
        return None
    return {'prefix': mfg[0:2].hex(), 'model': u16(mfg, 2), 'rec': mfg[4],
            'nonce': u16(mfg, 5), 'keychk': mfg[7], 'enc_len': len(mfg) - 8}


# ---------------------------------------------------------------- libs ----

def aes_pycryptodome(pkg):
    mod = importlib.import_module(pkg + '.Cipher.AES')
    return mod.new(AES_KEY, mod.MODE_ECB).encrypt(AES_PT), ''


def aes_cryptography():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    try:
        c = Cipher(algorithms.AES(AES_KEY), modes.ECB())
    except TypeError:   # cryptography < 3.1 : backend obligatoire
        from cryptography.hazmat.backends import default_backend
        c = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    e = c.encryptor()
    return e.update(AES_PT) + e.finalize(), ''


def load_libcrypto():
    import ctypes
    import ctypes.util
    names = ['libcrypto.so.3', 'libcrypto.so.1.1', 'libcrypto.so']
    try:
        found = ctypes.util.find_library('crypto')
    except Exception:
        found = None
    if found:
        names.insert(0, found)
    for n in names:
        try:
            return n, ctypes.CDLL(n)
        except OSError:
            pass
    raise ImportError('libcrypto introuvable (%s)' % ', '.join(names))


def aes_libcrypto():
    import ctypes
    name, lib = load_libcrypto()
    vp = ctypes.c_void_p
    ver = '?'
    for fn in ('OpenSSL_version', 'SSLeay_version'):
        f = getattr(lib, fn, None)
        if f is not None:
            f.restype = ctypes.c_char_p
            f.argtypes = [ctypes.c_int]
            ver = f(0).decode('ascii', 'replace')
            break
    lib.EVP_CIPHER_CTX_new.restype = vp
    lib.EVP_aes_128_ecb.restype = vp
    lib.EVP_EncryptInit_ex.argtypes = [vp, vp, vp, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_CIPHER_CTX_set_padding.argtypes = [vp, ctypes.c_int]
    lib.EVP_EncryptUpdate.argtypes = [vp, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
                                      ctypes.c_char_p, ctypes.c_int]
    lib.EVP_CIPHER_CTX_free.argtypes = [vp]
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError('EVP_CIPHER_CTX_new a echoue')
    try:
        if lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_128_ecb(), None, AES_KEY, None) != 1:
            raise RuntimeError('EVP_EncryptInit_ex a echoue')
        lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        buf = ctypes.create_string_buffer(32)
        n = ctypes.c_int(0)
        if lib.EVP_EncryptUpdate(ctx, buf, ctypes.byref(n), AES_PT, len(AES_PT)) != 1:
            raise RuntimeError('EVP_EncryptUpdate a echoue')
        return buf.raw[:n.value], '%s, %s' % (name, ver)
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def cmd_libs():
    res = {'python': sys.version.split()[0], 'mods': {}, 'aes': {}, 'velib': {}}
    print('python3                : %s (%s)' % (res['python'], sys.executable))
    print('--- modules ---')

    def probe(label, loader, version):
        try:
            m = loader()
            ver = version(m)
            res['mods'][label] = ver
            print('  %-20s : %-12s %s' % (label, ver, getattr(m, '__file__', '') or ''))
        except Exception as e:
            res['mods'][label] = 'absent'
            print('  %-20s : absent (%s)' % (label, err(e)))

    def imp(name):
        return lambda: importlib.import_module(name)

    def attr_version(m):
        return str(getattr(m, '__version__', '') or '?')

    probe('Crypto', imp('Crypto'), attr_version)
    probe('Cryptodome', imp('Cryptodome'), attr_version)
    probe('cryptography', imp('cryptography'), attr_version)
    probe('dbus', imp('dbus'), attr_version)
    probe('dbus.mainloop.glib', imp('dbus.mainloop.glib'),
          lambda m: 'OK' if hasattr(m, 'DBusGMainLoop') else 'sans DBusGMainLoop')
    probe('gi', imp('gi'), attr_version)
    probe('gi.repository.GLib', lambda: __import__('gi.repository', fromlist=['GLib']).GLib,
          lambda m: '%d.%d.%d' % (m.MAJOR_VERSION, m.MINOR_VERSION, m.MICRO_VERSION))
    probe('ssl', imp('ssl'), lambda m: m.OPENSSL_VERSION)

    print('--- AES-128 sur un bloc (ECB), vecteur NIST SP 800-38A F.1.1 ---')
    tests = (('pycryptodome', lambda: aes_pycryptodome('Crypto')),
             ('pycryptodomex', lambda: aes_pycryptodome('Cryptodome')),
             ('cryptography', aes_cryptography),
             ('libcrypto/ctypes', aes_libcrypto))
    for name, fn in tests:
        extra = ''
        try:
            out, extra = fn()
            status = 'OK' if out == AES_CT else 'RESULTAT FAUX (%s)' % out.hex()
        except ImportError as e:
            status = 'absent'
            extra = str(e) if name == 'libcrypto/ctypes' else ''
        except Exception as e:
            status = 'erreur'
            extra = err(e)
        res['aes'][name] = status
        print('  %-20s : %-8s %s' % (name, status, extra))

    print('--- velib_python ---')
    v = res['velib']
    vf = os.path.join(VELIB, 'vedbus.py')
    if not os.path.isfile(vf):
        v['ok'] = False
        print('  %s : ABSENT' % vf)
    else:
        try:
            import inspect
            sys.path.insert(1, VELIB)
            import vedbus
            sig = str(inspect.signature(vedbus.VeDbusService.__init__))
            v.update(ok=True, VeDbusService=sig)
            print('  vedbus.py            : %s' % vedbus.__file__)
            print('  VeDbusService        : %s' % sig)
            try:
                import settingsdevice
                print('  SettingsDevice       : %s'
                      % inspect.signature(settingsdevice.SettingsDevice.__init__))
            except Exception as e:
                print('  settingsdevice       : %s' % err(e))
        except Exception as e:
            v.update(ok=False, error=err(e))
            print('  import vedbus        : ECHEC (%s)' % err(e))
    copies = sorted(glob.glob('/opt/victronenergy/*/ext/velib_python/vedbus.py'))
    digests = set()
    for f in copies:
        try:
            with open(f, 'rb') as fh:
                digests.add(hashlib.sha1(fh.read()).hexdigest())
        except OSError:
            pass
    print('  copies de vedbus.py  : %d dans /opt/victronenergy, %d version(s) distincte(s)'
          % (len(copies), len(digests)))
    save_res('libs', res)


# --------------------------------------------------------------- bluez ----

def cmd_bluez():
    res = {'ok': False}
    try:
        import dbus
        bus = dbus.SystemBus()
        owner = bus.get_name_owner('org.bluez')
    except Exception as e:
        print('org.bluez : INJOIGNABLE sur le D-Bus systeme (%s)' % err(e))
        res['error'] = err(e)
        save_res('bluez', res)
        return
    print('org.bluez : present sur le D-Bus systeme (proprietaire %s)' % owner)
    try:
        om = dbus.Interface(bus.get_object('org.bluez', '/'), 'org.freedesktop.DBus.ObjectManager')
        objs = om.GetManagedObjects(timeout=10)
    except Exception as e:
        print('GetManagedObjects : ECHEC (%s)' % err(e))
        res['error'] = err(e)
        save_res('bluez', res)
        return
    res['ok'] = True
    res['adapters'] = {}
    adapters = sorted((str(p), i) for p, i in objs.items() if 'org.bluez.Adapter1' in i)
    if not adapters:
        print('aucun adaptateur (org.bluez.Adapter1)')
    for path, ifs in adapters:
        a = ifs['org.bluez.Adapter1']
        name = path.rsplit('/', 1)[-1]
        info = dict((k, py(a[k])) for k in ('Address', 'AddressType', 'Name', 'Alias', 'Powered',
                                             'Discoverable', 'Pairable', 'Discovering', 'Roles')
                    if k in a)
        print('--- adaptateur %s (%s)' % (name, path))
        for k, val in info.items():
            print('  %-14s : %s' % (k, val))
        others = sorted(str(k) for k in ifs if not str(k).startswith('org.freedesktop.DBus.'))
        print('  %-14s : %s' % ('interfaces', ', '.join(others)))
        try:
            ad = dbus.Interface(bus.get_object('org.bluez', path), 'org.bluez.Adapter1')
            filters = py(ad.GetDiscoveryFilters(timeout=10))
        except Exception as e:
            filters = 'indisponible (%s)' % err(e)
        info['filters'] = filters
        print('  %-14s : %s' % ('filtres decouverte', filters))
        if 'org.bluez.AdvertisementMonitorManager1' in ifs:
            m = ifs['org.bluez.AdvertisementMonitorManager1']
            info['adv_monitor'] = {'types': py(m.get('SupportedMonitorTypes')),
                                   'features': py(m.get('SupportedFeatures'))}
            print('  %-14s : types=%s fonctions=%s' % ('AdvMonitor', info['adv_monitor']['types'],
                                                       info['adv_monitor']['features']))
        res['adapters'][name] = info

    devs = [(str(p), i['org.bluez.Device1']) for p, i in objs.items() if 'org.bluez.Device1' in i]
    vic = [(p, d) for p, d in devs if mfg_from_dbus(d.get('ManufacturerData')) is not None]
    print('--- cache BlueZ : %d appareil(s), dont %d avec donnees fabricant Victron (0x02E1)'
          % (len(devs), len(vic)))
    for p, d in sorted(vic):
        mfg = mfg_from_dbus(d.get('ManufacturerData'))
        print('  %s  %-7s rssi=%-4s paired=%s trusted=%s connected=%s nom=%s' % (
            py(d.get('Address')), py(d.get('AddressType')), py(d.get('RSSI', '-')),
            py(d.get('Paired')), py(d.get('Trusted')), py(d.get('Connected')),
            py(d.get('Alias', d.get('Name', '-')))))
        print('      mfg=%s' % mfg.hex())
        if py(d.get('Paired')) or py(d.get('Connected')):
            print('      ATTENTION : appareil appaire ou connecte au GX')
    res['cached_devices'] = len(devs)
    res['cached_victron'] = len(vic)
    save_res('bluez', res)


# --------------------------------------------------------------- venus ----

def getv(bus, name, path):
    try:
        return py(bus.get_object(name, path, introspect=False)
                  .GetValue(dbus_interface=BUSITEM, timeout=5))
    except Exception:
        return None


def settings_items(bus):
    try:
        items = bus.get_object(SETTINGS, '/', introspect=False).GetItems(
            dbus_interface=BUSITEM, timeout=10)
        return dict((str(k), py(v.get('Value'))) for k, v in items.items())
    except Exception:
        pass
    try:
        v = py(bus.get_object(SETTINGS, '/Settings', introspect=False).GetValue(
            dbus_interface=BUSITEM, timeout=10))
        if isinstance(v, dict):
            return dict(('/Settings/' + k, x) for k, x in v.items())
    except Exception:
        pass
    return None


def cmd_venus():
    import textwrap
    try:
        import dbus
        bus = dbus.SystemBus()
        names = sorted(str(n) for n in bus.list_names() if str(n).startswith('com.victronenergy.'))
    except Exception as e:
        print('D-Bus systeme injoignable (%s)' % err(e))
        return
    print('%d services com.victronenergy.* :' % len(names))
    print(textwrap.fill(', '.join(n[len('com.victronenergy.'):] for n in names), 100,
                        initial_indent='  ', subsequent_indent='  '))
    print('--- appareils deja publies (ProductId = identifiant modele, comparable a celui des annonces BLE)')
    found = []
    for n in names:
        if n.split('.')[2] not in DEV_CLASSES:
            continue
        v = dict((p, getv(bus, n, p)) for p in DEV_PATHS)
        pid = v['/ProductId']
        found.append({'service': n, 'pid': pid, 'connection': v['/Mgmt/Connection']})
        print('  %s' % n)
        print('      instance=%s pid=%s nom=%s nom_perso=%s serie=%s fw=%s' % (
            show(v['/DeviceInstance']), '0x%04X' % pid if isinstance(pid, int) else show(pid),
            show(v['/ProductName']), show(v['/CustomName']), show(v['/Serial']),
            show(v['/FirmwareVersion'])))
        print('      connexion=%s processus=%s connecte=%s' % (
            show(v['/Mgmt/Connection']), show(v['/Mgmt/ProcessName']), show(v['/Connected'])))
    if not found:
        print('  aucun')
    print('--- reglages Bluetooth de Venus')
    for p in ('/Settings/Services/Bluetooth', '/Settings/Services/BleSensors'):
        print('  %-30s = %s' % (p, show(getv(bus, SETTINGS, p))))
    items = settings_items(bus)
    if items is None:
        print('  lecture globale des reglages impossible (GetItems / GetValue)')
    else:
        cvi = sorted((k, v) for k, v in items.items() if k.endswith('/ClassAndVrmInstance'))
        print('--- ClassAndVrmInstance deja attribues (%d)' % len(cvi))
        for k, v in cvi:
            print('  %s = %s' % (k, v))
        ble = sorted((k, v) for k, v in items.items()
                     if re.search(r'ble|bluetooth', k, re.I)
                     and not k.endswith('/ClassAndVrmInstance')
                     and not k.startswith('/Settings/Services/'))
        print('--- autres reglages contenant ble/bluetooth (%d)' % len(ble))
        for k, v in ble[:40]:
            print('  %s = %s' % (k, v))
        if len(ble) > 40:
            print('  ... %d de plus' % (len(ble) - 40))
    save_res('venus', {'devices': found})


# ---------------------------------------------------- watch / discover ----

def path_mac(path):
    return str(path).rsplit('/', 1)[-1].replace('dev_', '').replace('_', ':')


class DeviceWatcher(object):
    """Suit les mises a jour ManufacturerData[0x02E1] que BlueZ publie sur org.bluez.Device1."""

    def __init__(self, bus, out_path):
        self.t0 = time.time()
        self.stats = {}
        self.last_rssi = {}
        self.counters = {'added': 0, 'changed': 0, 'removed': 0, 'mfg_non_victron': 0}
        self.adapter_changes = []
        self.out = open(out_path, 'w')
        bus.add_signal_receiver(self.on_added, signal_name='InterfacesAdded', bus_name='org.bluez',
                                dbus_interface='org.freedesktop.DBus.ObjectManager')
        bus.add_signal_receiver(self.on_removed, signal_name='InterfacesRemoved', bus_name='org.bluez',
                                dbus_interface='org.freedesktop.DBus.ObjectManager')
        bus.add_signal_receiver(self.on_changed, signal_name='PropertiesChanged', bus_name='org.bluez',
                                dbus_interface='org.freedesktop.DBus.Properties', path_keyword='path')

    def elapsed(self):
        return time.time() - self.t0

    def handle(self, path, kind, md):
        try:
            data = mfg_from_dbus(md)
            if data is None:
                self.counters['mfg_non_victron'] += 1
                return
            mac = path_mac(path)
            s = self.stats.setdefault(mac, {'updates': 0, 'payloads': set(), 'ir_updates': 0,
                                            'ir_nonces': set()})
            s['updates'] += 1
            s['payloads'].add(data.hex())
            h = victron_header(data)
            if h:
                s['ir_updates'] += 1
                s['ir_nonces'].add(h['nonce'])
            self.out.write(json.dumps({'t': round(self.elapsed(), 3), 'sig': kind, 'mac': mac,
                                       'rssi': self.last_rssi.get(str(path)), 'mfg': data.hex()}) + '\n')
        except Exception as e:
            print('signal ignore (%s)' % err(e))

    def on_added(self, path, ifaces):
        dev = ifaces.get('org.bluez.Device1')
        if dev is None:
            return
        self.counters['added'] += 1
        if 'RSSI' in dev:
            self.last_rssi[str(path)] = int(dev['RSSI'])
        if 'ManufacturerData' in dev:
            self.handle(path, 'added', dev['ManufacturerData'])

    def on_removed(self, path, ifaces):
        if 'org.bluez.Device1' in ifaces:
            self.counters['removed'] += 1

    def on_changed(self, iface, changed, invalidated, path=None):
        if iface == 'org.bluez.Adapter1':
            if 'Discovering' in changed:
                self.adapter_changes.append('+%.1f s Discovering=%s'
                                            % (self.elapsed(), bool(changed['Discovering'])))
            return
        if iface != 'org.bluez.Device1':
            return
        self.counters['changed'] += 1
        if 'RSSI' in changed:
            self.last_rssi[str(path)] = int(changed['RSSI'])
        if 'ManufacturerData' in changed:
            self.handle(path, 'changed', changed['ManufacturerData'])

    def report(self):
        self.out.close()
        elapsed = self.elapsed()
        c = self.counters
        print('signaux Device1 : %d ajouts, %d PropertiesChanged, %d retraits, %d maj mfg non Victron'
              % (c['added'], c['changed'], c['removed'], c['mfg_non_victron']))
        for a in self.adapter_changes:
            print('adaptateur : %s' % a)
        print('mises a jour ManufacturerData[0x02E1] par appareil :')
        if not self.stats:
            print('  aucune')
        for mac, s in sorted(self.stats.items(), key=lambda x: -x[1]['updates']):
            print('  %s : %d mises a jour (%.1f/s), %d charges distinctes, dont %d IR (%d nonces)'
                  % (mac, s['updates'], s['updates'] / max(elapsed, 0.1), len(s['payloads']),
                     s['ir_updates'], len(s['ir_nonces'])))
        return {'duration': round(elapsed, 1), 'counters': c, 'adapter_changes': self.adapter_changes,
                'victron': dict((m, {'updates': s['updates'], 'distinct': len(s['payloads']),
                                     'ir_updates': s['ir_updates'], 'ir_nonces': sorted(s['ir_nonces'])})
                                for m, s in self.stats.items())}


def cmd_discover(duration):
    res = {'ran': False}
    try:
        import dbus
        from dbus.mainloop.glib import DBusGMainLoop
        from gi.repository import GLib
        DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        ad_obj = bus.get_object('org.bluez', '/org/bluez/hci0')
        props = dbus.Interface(ad_obj, 'org.freedesktop.DBus.Properties')
        powered = bool(props.Get('org.bluez.Adapter1', 'Powered', timeout=10))
        res['discovering_before'] = bool(props.Get('org.bluez.Adapter1', 'Discovering', timeout=10))
    except Exception as e:
        res['reason'] = 'hci0 inaccessible (%s)' % err(e)
        print('test saute : %s' % res['reason'])
        save_res('discovery', res)
        return
    if not powered:
        res['reason'] = 'hci0 non alimente (Powered=0) ; le script ne le rallume pas'
        print('test saute : %s' % res['reason'])
        save_res('discovery', res)
        return
    adapter = dbus.Interface(ad_obj, 'org.bluez.Adapter1')
    res['filter_errors'] = []
    for f in ({'Transport': 'le', 'DuplicateData': True}, {'Transport': 'le'}):
        try:
            adapter.SetDiscoveryFilter(dbus.Dictionary(f, signature='sv'), timeout=10)
            res['filter'] = f
            break
        except dbus.exceptions.DBusException as e:
            res['filter_errors'].append('%s -> %s' % (f, e.get_dbus_name()))
    print('Discovering avant le test : %s' % res['discovering_before'])
    print('filtre accepte : %s' % res.get('filter', 'AUCUN'))
    for e in res['filter_errors']:
        print('filtre refuse  : %s' % e)
    watcher = DeviceWatcher(bus, os.path.join(OUT, 'discovery_dbus.jsonl'))
    try:
        adapter.StartDiscovery(timeout=10)
    except dbus.exceptions.DBusException as e:
        res['reason'] = 'StartDiscovery refuse : %s (%s)' % (e.get_dbus_name(), e.get_dbus_message())
        print(res['reason'])
        watcher.report()
        save_res('discovery', res)
        return
    res['ran'] = True
    watcher.t0 = time.time()
    print('decouverte demarree pour %d s...' % duration)
    loop = GLib.MainLoop()
    GLib.timeout_add_seconds(duration, loop.quit)
    try:
        loop.run()
    except KeyboardInterrupt:
        print('interrompu')
    finally:
        try:
            adapter.StopDiscovery(timeout=10)
            print('decouverte arretee')
        except dbus.exceptions.DBusException as e:
            print('StopDiscovery : %s' % e.get_dbus_name())
    res.update(watcher.report())
    save_res('discovery', res)


# -------------------------------------------------------------- advmon ----

# Donnees fabricant (type AD 0xFF) commencant par e1 02 (Victron) puis 0x10 (trame Instant Readout)
ADVMON_PATTERN = (0, 0xFF, b'\xe1\x02\x10')


def cmd_advmon(label, duration):
    """Scan passif BlueZ : un AdvertisementMonitor (or_patterns) limite aux trames Instant Readout.
    Ni connexion ni appairage ; BlueZ retire le moniteur a la deconnexion du client."""
    key = 'advmon_' + label
    res = {'ran': False, 'events': []}
    try:
        import dbus
        import dbus.service
        from dbus.mainloop.glib import DBusGMainLoop
        from gi.repository import GLib
        DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        hci = bus.get_object('org.bluez', '/org/bluez/hci0')
        props = dbus.Interface(hci, 'org.freedesktop.DBus.Properties')
        res['discovering_before'] = bool(props.Get('org.bluez.Adapter1', 'Discovering', timeout=10))
        res['types'] = py(props.Get('org.bluez.AdvertisementMonitorManager1', 'SupportedMonitorTypes',
                                    timeout=10))
        mgr = dbus.Interface(hci, 'org.bluez.AdvertisementMonitorManager1')
    except Exception as e:
        res['reason'] = 'AdvertisementMonitorManager1 inaccessible (%s)' % err(e)
        print('test saute : %s' % res['reason'])
        save_res(key, res)
        return
    print('Discovering avant le test : %s ; types de moniteur : %s'
          % (res['discovering_before'], res['types']))

    MON_IF = 'org.bluez.AdvertisementMonitor1'
    PROPS_IF = 'org.freedesktop.DBus.Properties'
    loop = GLib.MainLoop()
    watcher = DeviceWatcher(bus, os.path.join(OUT, label + '_dbus.jsonl'))
    state = {'active': None, 'objs': [], 'apps': []}

    def ev(kind, detail=''):
        res['events'].append([round(watcher.elapsed(), 2), kind, str(detail)])
        print('  +%6.2f s %s %s' % (watcher.elapsed(), kind, detail))

    class Monitor(dbus.service.Object):
        def __init__(self, path, mprops):
            self.path = path
            self.mprops = mprops
            dbus.service.Object.__init__(self, bus, path)

        @dbus.service.method(MON_IF, in_signature='', out_signature='')
        def Release(self):
            ev('Release', self.path)

        @dbus.service.method(MON_IF, in_signature='', out_signature='')
        def Activate(self):
            state['active'] = self.path
            ev('Activate', self.path)

        @dbus.service.method(MON_IF, in_signature='o', out_signature='')
        def DeviceFound(self, device):
            ev('DeviceFound', path_mac(device))

        @dbus.service.method(MON_IF, in_signature='o', out_signature='')
        def DeviceLost(self, device):
            ev('DeviceLost', path_mac(device))

        @dbus.service.method(PROPS_IF, in_signature='s', out_signature='a{sv}')
        def GetAll(self, iface):
            return self.mprops if iface == MON_IF else dbus.Dictionary({}, signature='sv')

        @dbus.service.method(PROPS_IF, in_signature='ss', out_signature='v')
        def Get(self, iface, name):
            return self.mprops[name]

    class App(dbus.service.Object):
        def __init__(self, path, mon):
            self.mon = mon
            dbus.service.Object.__init__(self, bus, path)

        @dbus.service.method('org.freedesktop.DBus.ObjectManager', in_signature='',
                             out_signature='a{oa{sa{sv}}}')
        def GetManagedObjects(self):
            return {dbus.ObjectPath(self.mon.path): {MON_IF: self.mon.mprops}}

    start, adtype, content = ADVMON_PATTERN
    pattern = dbus.Struct((dbus.Byte(start), dbus.Byte(adtype),
                           dbus.Array([dbus.Byte(b) for b in bytearray(content)], signature='y')),
                          signature='yyay')
    base = {'Type': dbus.String('or_patterns'), 'Patterns': dbus.Array([pattern], signature='(yyay)')}
    variants = [('RSSISamplingPeriod=0 (toutes les annonces)', dict(base, RSSISamplingPeriod=dbus.UInt16(0))),
                ('sans parametre RSSI', dict(base))]

    def attempt(i):
        name, mprops = variants[i]
        app_path = '/org/venus_ble_diag/%s%d' % (label, i)
        mon = Monitor(app_path + '/m0', dbus.Dictionary(mprops, signature='sv'))
        state['objs'].extend([App(app_path, mon), mon])
        state['apps'].append(app_path)
        ev('RegisterMonitor', name)
        mgr.RegisterMonitor(dbus.ObjectPath(app_path),
                            reply_handler=lambda: ev('RegisterMonitor', 'accepte'),
                            error_handler=lambda e: ev('RegisterMonitor', 'ERREUR %s' % err(e)))
        GLib.timeout_add_seconds(5, check, i)

    def check(i):
        if state['active']:
            res['variant'] = variants[i][0]
            res['measure_start'] = round(watcher.elapsed(), 2)
            ev('mesure', '%d s' % duration)
            GLib.timeout_add_seconds(duration, loop.quit)
        elif i + 1 < len(variants):
            attempt(i + 1)
        else:
            ev('ECHEC', 'aucune variante activee en 5 s')
            loop.quit()
        return False

    attempt(0)
    try:
        loop.run()
    except KeyboardInterrupt:
        print('interrompu')
    finally:
        for p in state['apps']:
            try:
                mgr.UnregisterMonitor(dbus.ObjectPath(p), timeout=5)
            except Exception as e:
                print('UnregisterMonitor %s : %s' % (p, err(e)))
    res['ran'] = bool(state['active'])
    res.update(watcher.report())
    save_res(key, res)


# -------------------------------------------------------------- hcimon ----

def adv_reports(ev):
    """Evenement HCI (code, longueur, parametres) -> (sous-evenement, rapports d'annonce)."""
    if len(ev) < 2 or ev[0] != 0x3E:
        return None, []
    p = ev[2:2 + ev[1]]
    if len(p) < 2:
        return None, []
    if p[0] == 0x02:
        return 0x02, list(legacy_reports(p))
    if p[0] == 0x0D:
        return 0x0D, list(ext_reports(p))
    return p[0], []


def cmd_hcimon(label, seconds):
    """Lecture directe du canal moniteur HCI (celui de btmon) depuis Python.
    Ecoute seule, aucune commande envoyee au controleur. S'arrete apres SECONDES ou sur SIGTERM."""
    import ctypes
    import select
    import signal
    import socket
    key = 'hcimon_' + label
    res = {'ok': False}
    stop = [False]
    signal.signal(signal.SIGTERM, lambda *a: stop.__setitem__(0, True))
    af = getattr(socket, 'AF_BLUETOOTH', 31)
    proto = getattr(socket, 'BTPROTO_HCI', 1)
    s = None
    try:
        s = socket.socket(af, socket.SOCK_RAW, proto)
        # struct sockaddr_hci { sa_family_t family; u16 dev; u16 channel; } : HCI_DEV_NONE, HCI_CHANNEL_MONITOR
        addr = struct.pack('=HHH', af, 0xFFFF, 2)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.bind.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        if libc.bind(s.fileno(), addr, len(addr)) != 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))
        res['ok'] = True
        stats = {}
        n = nadv = bad = 0
        t0 = time.time()
        while not stop[0] and time.time() < t0 + seconds:
            r, _, _ = select.select([s], [], [], 0.5)
            if not r:
                continue
            data = s.recv(65535)
            n += 1
            if len(data) < 8 or u16(data, 0) != 3:   # hci_mon_hdr : opcode, index, len ; 3 = evenement
                continue
            try:
                sub, reports = adv_reports(data[6:])
            except (IndexError, struct.error, ValueError):
                bad += 1
                continue
            nadv += len(reports)
            for evt, atype, a, rssi, ad in reports:
                mfg = victron_mfg(ad)
                h = victron_header(mfg) if mfg else None
                if h:
                    st = stats.setdefault(fmt_mac(a), {'ir_frames': 0, 'ir_nonces': set()})
                    st['ir_frames'] += 1
                    st['ir_nonces'].add(h['nonce'])
        dur = time.time() - t0
        res.update(duration=round(dur, 1), packets=n, adv_reports=nadv, bad=bad,
                   victron=dict((m, {'ir_frames': v['ir_frames'], 'ir_nonces': sorted(v['ir_nonces'])})
                                for m, v in stats.items()))
        print('[%s] socket moniteur HCI (Python) : %d paquets en %.0f s, %d rapports d\'annonce, '
              '%d illisibles' % (label, n, dur, nadv, bad))
        for m, v in sorted(stats.items()):
            print('    %s : %d trames IR, %d nonces' % (m, v['ir_frames'], len(v['ir_nonces'])))
    except Exception as e:
        res['error'] = err(e)
        print('[%s] socket moniteur HCI (Python) : IMPOSSIBLE (%s)' % (label, err(e)))
    finally:
        if s is not None:
            s.close()
    save_res(key, res)


# ------------------------------------------------------------- setting ----

def cmd_setting(path, value=None):
    """Lit (et ecrit si VALUE est donne) un reglage entier de com.victronenergy.settings."""
    import dbus
    try:
        obj = dbus.SystemBus().get_object(SETTINGS, path, introspect=False)
        if value is not None:
            obj.SetValue(dbus.Int32(int(value)), dbus_interface=BUSITEM, timeout=10)
        print(py(obj.GetValue(dbus_interface=BUSITEM, timeout=10)))
    except Exception as e:   # absent setting: nothing on stdout, the caller shows an empty value
        sys.stderr.write('setting %s : %s\n' % (path, err(e)))
        sys.exit(1)


def cmd_names():
    import dbus
    for n in sorted(str(x) for x in dbus.SystemBus().list_names()):
        if n.startswith('com.victronenergy.'):
            print(n)


# ------------------------------------------------------------- analyze ----

def read_btsnoop(path):
    with open(path, 'rb') as f:
        hdr = f.read(16)
        if len(hdr) < 16 or hdr[:8] != b'btsnoop\x00':
            raise ValueError('pas un fichier btsnoop')
        dlt = struct.unpack('>I', hdr[12:16])[0]
        while True:
            rh = f.read(24)
            if len(rh) < 24:
                return
            orig, incl, flags, drops, ts = struct.unpack('>IIIIq', rh)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield dlt, flags, drops, ts, data


def legacy_reports(p):
    """LE Advertising Report (sous-evenement 0x02), decoupe comme le noyau Linux."""
    off = 2
    for _ in range(p[1]):
        evt, atype, addr, dlen = p[off], p[off + 1], p[off + 2:off + 8], p[off + 8]
        ad = p[off + 9:off + 9 + dlen]
        if len(ad) < dlen:
            raise ValueError('rapport tronque')
        off += 9 + dlen
        rssi = struct.unpack_from('b', p, off)[0]
        off += 1
        yield LEGACY_EVT.get(evt, 'evt0x%02x' % evt), atype, addr, rssi, ad


def ext_reports(p):
    """LE Extended Advertising Report (sous-evenement 0x0D)."""
    off = 2
    for _ in range(p[1]):
        evt, atype, addr = u16(p, off), p[off + 2], p[off + 3:off + 9]
        rssi = struct.unpack_from('b', p, off + 13)[0]
        dlen = p[off + 23]
        ad = p[off + 24:off + 24 + dlen]
        if len(ad) < dlen:
            raise ValueError('rapport tronque')
        off += 24 + dlen
        if evt & 0x10:
            name = 'ext/' + EXT_LEGACY_EVT.get(evt & 0x1F, '0x%04x' % evt)
        else:
            name = 'ext/0x%04x' % evt
        yield name, atype, addr, rssi, ad


def victron_mfg(ad):
    i = 0
    while i < len(ad):
        ln = ad[i]
        if ln == 0 or i + 1 + ln > len(ad):
            return None
        typ, val = ad[i + 1], ad[i + 2:i + 1 + ln]
        if typ == 0xFF and len(val) >= 2 and u16(val, 0) == VICTRON_CID:
            return val[2:]
        i += 1 + ln
    return None


def addr_kind(atype, addr):
    # Les 2 bits de poids fort d'une adresse aleatoire en donnent la nature ; une adresse
    # resolvable change periodiquement, ce qui rendrait une liste blanche par MAC inutilisable.
    if atype in (0, 2):
        return 'public'
    if atype in (1, 3):
        return {3: 'random-static', 1: 'random-RESOLVABLE', 0: 'random-nonresolv'}.get(
            addr[5] >> 6, 'random-?')
    return 'type0x%02x' % atype


def ms(v):
    return v * 0.625


def decode_scan_cmd(op, p):
    try:
        if op == 0x200B:
            return 'LE Set Scan Parameters : %s, intervalle %.2f ms, fenetre %.2f ms, politique %d' % (
                SCAN_TYPE.get(p[0], p[0]), ms(u16(p, 1)), ms(u16(p, 3)), p[6])
        if op == 0x200C:
            return 'LE Set Scan Enable : enable=%d filtre_doublons=%d' % (p[0], p[1])
        if op == 0x2041:
            parts, off = [], 3
            for bit, phy in ((0, '1M'), (2, 'Coded')):
                if p[2] & (1 << bit):
                    parts.append('%s %s %.2f/%.2f ms' % (phy, SCAN_TYPE.get(p[off], p[off]),
                                                         ms(u16(p, off + 1)), ms(u16(p, off + 3))))
                    off += 5
            return 'LE Set Extended Scan Parameters : %s, politique %d' % ('; '.join(parts) or '?', p[1])
        if op == 0x2042:
            return 'LE Set Extended Scan Enable : enable=%d filtre_doublons=%d duree=%d periode=%d' % (
                p[0], p[1], u16(p, 2), u16(p, 4))
    except (IndexError, struct.error):
        return 'commande 0x%04X tronquee' % op
    return None


def set_status(scan, op, status):
    for c in reversed(scan):
        if c['op'] == op and c['status'] is None:
            c['status'] = status
            return


def analyze_file(label, path, jsonl):
    st = {'events': 0, 'legacy': 0, 'ext': 0, 'bad': 0, 'drops': 0}
    t_first = t_last = None
    addrs = set()
    ctrls = {}
    scan = []
    vic = {}
    for dlt, flags, drops, ts, data in read_btsnoop(path):
        if dlt != 2001:
            raise ValueError('format btsnoop %d non gere (btmon -w ecrit 2001)' % dlt)
        t = (ts - BTSNOOP_EPOCH_1970) / 1e6
        if t_first is None:
            t_first = t
        t_last = t
        rel = t - t_first
        st['drops'] = max(st['drops'], drops)
        opcode, index = flags & 0xFFFF, flags >> 16
        try:
            if opcode == 0 and len(data) >= 16:            # NEW_INDEX
                name = data[8:16].split(b'\0')[0].decode('ascii', 'replace')
                ctrls[index] = '%s %s' % (name, fmt_mac(data[2:8]))
            elif opcode == 2 and len(data) >= 3:           # COMMAND
                op = u16(data, 0)
                txt = decode_scan_cmd(op, data[3:3 + data[2]])
                if txt:
                    scan.append({'t': round(rel, 2), 'hci': index, 'op': op, 'cmd': txt,
                                 'status': None, 'p': data[3:3 + data[2]].hex()})
            elif opcode == 3 and len(data) >= 2:           # EVENT
                st['events'] += 1
                code, p = data[0], data[2:2 + data[1]]
                if code == 0x0E and len(p) >= 4:           # Command Complete
                    set_status(scan, u16(p, 1), p[3])
                elif code == 0x0F and len(p) >= 4:         # Command Status
                    set_status(scan, u16(p, 2), p[0])
                elif code == 0x3E:
                    sub, reports = adv_reports(data)
                    st['legacy' if sub == 0x02 else 'ext'] += len(reports)
                    for evt, atype, addr, rssi, ad in reports:
                        mac = fmt_mac(addr)
                        addrs.add(mac)
                        mfg = victron_mfg(ad)
                        if mfg is None:
                            continue
                        s = vic.get(mac)
                        if s is None:
                            s = vic[mac] = {'count': 0, 'ir': 0, 'rssi': [], 'evt': set(), 'lens': set(),
                                            'payloads': set(), 'nonces': set(), 'keychk': set(),
                                            'hdr': None, 'kind': addr_kind(atype, addr),
                                            'samples': [], 'byte0': mfg[0] if mfg else None}
                        s['count'] += 1
                        if rssi != 127:
                            s['rssi'].append(rssi)
                        s['evt'].add(evt)
                        s['lens'].add(len(mfg))
                        s['payloads'].add(mfg)
                        h = victron_header(mfg)
                        if h:
                            s['ir'] += 1
                            s['hdr'] = s['hdr'] or h
                            s['nonces'].add(h['nonce'])
                            s['keychk'].add(h['keychk'])
                        if len(s['samples']) < 3 and mfg.hex() not in s['samples']:
                            s['samples'].append(mfg.hex())
                        jsonl.write(json.dumps({
                            'phase': label, 't': round(rel, 3), 'ts': round(t, 3), 'hci': index,
                            'mac': mac, 'atype': atype, 'evt': evt, 'rssi': rssi,
                            'mfg': mfg.hex(), 'adv': ad.hex()}) + '\n')
        except (IndexError, struct.error, ValueError):
            st['bad'] += 1

    dur = (t_last - t_first) if t_first is not None else 0.0
    nrep = st['legacy'] + st['ext']
    print('[%s] %s : %d Ko, %.1f s, %d evenements HCI, %d illisibles, pertes btmon=%d' % (
        label, os.path.basename(path), os.path.getsize(path) // 1024, dur, st['events'],
        st['bad'], st['drops']))
    for i, c in sorted(ctrls.items()):
        print('  controleur index %d : %s' % (i, c))
    print('  rapports d\'annonce : %d (legacy %d, etendus %d), %d adresses distinctes, %.1f/s' % (
        nrep, st['legacy'], st['ext'], len(addrs), nrep / max(dur, 0.1)))
    if scan:
        print('  commandes de scan vues (%d) :' % len(scan))
        for c in scan[:15]:
            status = '?' if c['status'] is None else '0x%02X' % c['status']
            print('    +%7.2f s hci%d %s -> statut %s' % (c['t'], c['hci'], c['cmd'], status))
        if len(scan) > 15:
            print('    ... %d de plus' % (len(scan) - 15))
    else:
        print('  commandes de scan vues : aucune')
    print('  appareils Victron (0x02E1) : %d' % len(vic))
    summary = {'duration': round(dur, 1), 'reports': nrep, 'legacy': st['legacy'], 'ext': st['ext'],
               'addresses': len(addrs), 'bad': st['bad'], 'drops': st['drops'],
               'scan_cmds': scan, 'victron': {}}
    for mac, s in sorted(vic.items(), key=lambda x: -x[1]['count']):
        r = s['rssi']
        rs = '%d/%d/%d' % (min(r), sum(r) // len(r), max(r)) if r else '-'
        print('    %s %-17s %5d trames (%.1f/s) RSSI min/moy/max %s dBm [%s]' % (
            mac, s['kind'], s['count'], s['count'] / max(dur, 0.1), rs, ','.join(sorted(s['evt']))))
        h = s['hdr']
        if h:
            print('        Instant Readout : prefixe %s, modele 0x%04X, enregistrement 0x%02X (%s), '
                  'octet cle %s, chiffre %d o' % (
                      h['prefix'], h['model'], h['rec'], RECORD_TYPES.get(h['rec'], '?'),
                      '/'.join('0x%02X' % k for k in sorted(s['keychk'])), h['enc_len']))
            print('        nonces distincts %d (0x%04X..0x%04X), charges distinctes %d, longueurs %s' % (
                len(s['nonces']), min(s['nonces']), max(s['nonces']), len(s['payloads']),
                sorted(s['lens'])))
        else:
            print('        pas d\'en-tete Instant Readout (octet 0 = %s, 0x10 attendu) : '
                  'Instant Readout desactive ?' % (
                      '0x%02X' % s['byte0'] if s['byte0'] is not None else 'vide'))
        for x in s['samples']:
            print('        ex. %s' % x)
        summary['victron'][mac] = {
            'count': s['count'], 'distinct': len(s['payloads']), 'kind': s['kind'],
            'ir_frames': s['ir'], 'ir_nonces': sorted(s['nonces']),
            'model': h['model'] if h else None, 'rec': h['rec'] if h else None,
            'rssi_avg': sum(r) // len(r) if r else None}
    return summary


def cmd_analyze(args):
    with open(os.path.join(OUT, 'victron_adv.jsonl'), 'w') as jsonl:
        for label, path in zip(args[0::2], args[1::2]):
            if not os.path.isfile(path) or os.path.getsize(path) <= 16:
                print('[%s] pas de capture (%s)' % (label, path))
                continue
            try:
                save_res('capture_' + label, analyze_file(label, path, jsonl))
            except Exception as e:
                print('[%s] analyse impossible : %s' % (label, err(e)))


# ------------------------------------------------------------- summary ----

def cmd_summary():
    r = load_res()
    L = r.get('libs', {})
    mods = L.get('mods', {})

    def line(k, v):
        print('%-20s : %s' % (k, v))

    line('Venus OS', '%s (%s)' % (os.environ.get('DIAG_VENUS', '?'), os.environ.get('DIAG_MACHINE', '?')))
    line('Python', L.get('python', '?'))
    line('AES-128 (NIST)', ', '.join('%s %s' % kv for kv in L.get('aes', {}).items()) or '?')
    line('dbus / GLib', '%s / %s' % (mods.get('dbus', '?'), mods.get('gi.repository.GLib', '?')))
    v = L.get('velib', {})
    line('velib_python', ('OK, VeDbusService%s' % v.get('VeDbusService', '')) if v.get('ok')
         else 'PROBLEME (%s)' % v.get('error', 'absent'))
    bz = r.get('bluez', {})
    if not bz.get('ok'):
        line('BlueZ', 'INJOIGNABLE (%s)' % bz.get('error', 'non teste'))
    else:
        h = bz.get('adapters', {}).get('hci0')
        if h:
            line('BlueZ hci0', 'Powered=%s Discovering=%s, filtres %s' % (
                h.get('Powered'), h.get('Discovering'), h.get('filters')))
        else:
            line('BlueZ hci0', 'ABSENT (adaptateurs : %s)' % (', '.join(bz.get('adapters', {})) or 'aucun'))
        line('cache BlueZ', '%s appareils dont %s Victron' % (bz.get('cached_devices'), bz.get('cached_victron')))
    for label, title in (('passive', 'Ecoute passive'), ('discovery', 'Capture decouverte')):
        c = r.get('capture_' + label)
        if not c:
            line(title, 'pas de capture')
            continue
        frames = sum(x['count'] for x in c['victron'].values())
        line(title, '%d annonces, %d adresses en %.0f s ; Victron : %d appareil(s), %d trames' % (
            c['reports'], c['addresses'], c['duration'], len(c['victron']), frames))
        if label == 'passive':
            hm = r.get('hcimon_passive')
            if hm:
                print('%-20s   socket moniteur Python : %s' % ('', (
                    'OK, %s rapports d\'annonce pendant la meme fenetre' % hm.get('adv_reports'))
                    if hm.get('ok') else 'IMPOSSIBLE (%s)' % hm.get('error')))
            if c['reports'] == 0:
                print('%-20s   -> aucune annonce sans action du script : personne ne scanne en continu' % '')
            else:
                print('%-20s   -> des annonces arrivent sans action du script : un scan tourne deja' % '')
    d = r.get('discovery')
    if d is not None:
        if not d.get('ran'):
            line('Decouverte BlueZ', 'non lancee : %s' % d.get('reason', '?'))
        else:
            line('Decouverte BlueZ', 'filtre %s%s' % (d.get('filter'), (', refus : %s' % d['filter_errors'])
                                                       if d.get('filter_errors') else ''))
            cap = r.get('capture_discovery', {}).get('victron', {})
            macs = sorted(set(cap) | set(d.get('victron', {})))
            for mac in macs:
                b = cap.get(mac, {})
                u = d.get('victron', {}).get(mac, {})
                print('%-20s   %s : btmon %s trames / %s charges distinctes | D-Bus %s mises a jour' % (
                    '', mac, b.get('count', 0), b.get('distinct', 0), u.get('updates', 0)))


def scan_profile(cmds):
    """Commandes de scan -> liste ordonnee (sans doublons) de 'type cycle' et 'ON/OFF(doublons)'."""
    seen = []
    for c in cmds:
        try:
            p = bytes.fromhex(c.get('p', ''))
            if c['op'] == 0x200B:
                d = '%s, cycle %.0f %% (fenetre %.2f ms / intervalle %.2f ms)' % (
                    SCAN_TYPE.get(p[0], p[0]), 100.0 * u16(p, 3) / max(u16(p, 1), 1),
                    ms(u16(p, 3)), ms(u16(p, 1)))
            elif c['op'] == 0x2041:
                d = 'etendu %s, cycle %.0f %% (fenetre %.2f ms / intervalle %.2f ms)' % (
                    SCAN_TYPE.get(p[3], p[3]), 100.0 * u16(p, 6) / max(u16(p, 4), 1),
                    ms(u16(p, 6)), ms(u16(p, 4)))
            elif c['op'] in (0x200C, 0x2042):
                if not p[0]:
                    continue
                d = 'scan ON, filtre doublons=%d' % p[1]
            else:
                continue
        except (IndexError, struct.error, ValueError):
            continue
        if d not in seen:
            seen.append(d)
    return seen


def cmd_summary2():
    r = load_res()
    phases = (('advmon', 'M  : AdvertisementMonitor seul'),
              ('blesensors', 'S1 : capteurs Bluetooth de Venus seuls (B en conditions reelles)'),
              ('mixed', 'S2 : capteurs Bluetooth de Venus + AdvertisementMonitor'))
    for label, title in phases:
        c = r.get('capture_' + label)
        a = r.get('advmon_' + label)
        h = r.get('hcimon_' + label)
        if not (c or a or h):
            continue
        print('=== %s' % title)
        if c:
            print('  btmon    : %d rapports d\'annonce, %d adresses en %.0f s'
                  % (c['reports'], c['addresses'], c['duration']))
            prof = scan_profile(c.get('scan_cmds', []))
            print('  scan     : %s' % (' | '.join(prof) if prof else 'aucune commande de scan vue'))
            refused = [x for x in c.get('scan_cmds', []) if x.get('status') not in (None, 0)]
            for x in refused[:3]:
                print('  REFUS    : +%.1f s %s -> statut 0x%02X' % (x['t'], x['cmd'], x['status']))
        if a:
            if a.get('ran'):
                nf = sum(1 for e in a.get('events', []) if e[1] == 'DeviceFound')
                nl = sum(1 for e in a.get('events', []) if e[1] == 'DeviceLost')
                print('  moniteur : ACTIVE (%s), DeviceFound %d, DeviceLost %d'
                      % (a.get('variant'), nf, nl))
            else:
                last = a.get('events', [])[-3:]
                print('  moniteur : NON ACTIVE (%s)' % (a.get('reason') or last))
            if a.get('adapter_changes'):
                print('  adaptateur : %s' % ', '.join(a['adapter_changes']))
        if h and not h.get('ok'):
            print('  socket Python : IMPOSSIBLE (%s)' % h.get('error'))
        macs = sorted(set((c or {}).get('victron', {})) | set((a or {}).get('victron', {}))
                      | set((h or {}).get('victron', {})))
        for mac in macs:
            b = (c or {}).get('victron', {}).get(mac, {})
            bn = set(b.get('ir_nonces', []))
            parts = ['btmon %d trames IR / %d nonces' % (b.get('ir_frames', 0), len(bn))]
            if a:
                d = a.get('victron', {}).get(mac, {})
                parts.append('D-Bus %d maj IR, nonces %d/%d' % (
                    d.get('ir_updates', 0), len(set(d.get('ir_nonces', [])) & bn), len(bn)))
            if h and h.get('ok'):
                x = h.get('victron', {}).get(mac, {})
                parts.append('socket Python %d IR, nonces %d/%d' % (
                    x.get('ir_frames', 0), len(set(x.get('ir_nonces', [])) & bn), len(bn)))
            print('  %s : %s' % (mac, ' | '.join(parts)))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'libs':
        cmd_libs()
    elif cmd == 'bluez':
        cmd_bluez()
    elif cmd == 'venus':
        cmd_venus()
    elif cmd == 'discover':
        cmd_discover(int(sys.argv[2]))
    elif cmd == 'hcimon':
        cmd_hcimon(sys.argv[2], int(sys.argv[3]))
    elif cmd == 'advmon':
        cmd_advmon(sys.argv[2], int(sys.argv[3]))
    elif cmd == 'setting':
        cmd_setting(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == 'names':
        cmd_names()
    elif cmd == 'summary2':
        cmd_summary2()
    elif cmd == 'analyze':
        cmd_analyze(sys.argv[2:])
    elif cmd == 'summary':
        cmd_summary()
    else:
        print('commande inconnue : %s' % cmd)
        return 2
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print('ERREUR dans %s : %s' % (' '.join(sys.argv[1:2]), err(e)))
        sys.exit(1)
PYEOF

# ---------------------------------------------------------------------------
# Partie shell
# ---------------------------------------------------------------------------

section() {
    echo
    echo "############ $* ############"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# run_to SECONDES commande... : execute avec une limite de temps (sans dependre de timeout)
run_to() {
    t=$1
    shift
    "$@" &
    rt_pid=$!
    ( sleep "$t"; kill "$rt_pid" 2>/dev/null ) >/dev/null 2>&1 &
    rt_watch=$!
    wait "$rt_pid" 2>/dev/null
    rt_rc=$?
    kill "$rt_watch" 2>/dev/null
    return $rt_rc
}

# Attente interruptible : un signal piege interrompt « wait » tout de suite, alors qu'avec un
# sleep au premier plan le shell attendrait la fin du sleep avant de nettoyer.
pause() {
    sleep "$1" &
    SLEEP_PID=$!
    wait "$SLEEP_PID" 2>/dev/null
    SLEEP_PID=
}

# Un job lance en arriere-plan par un shell non interactif ignore SIGINT : on arrete btmon par TERM.
stop_btmon() {
    [ -n "$BTMON_PID" ] || return 0
    kill -TERM "$BTMON_PID" 2>/dev/null
    i=0
    while kill -0 "$BTMON_PID" 2>/dev/null && [ $i -lt 3 ]; do
        sleep 1
        i=$((i + 1))
    done
    kill -KILL "$BTMON_PID" 2>/dev/null
    wait "$BTMON_PID" 2>/dev/null
    BTMON_PID=
}

# start_btmon LIBELLE : capture HCI brute dans $OUT/LIBELLE.btsnoop
start_btmon() {
    "$BTMON" -w "$OUT/$1.btsnoop" > "$OUT/btmon_$1.txt" 2>&1 &
    BTMON_PID=$!
    sleep 1
    if ! kill -0 "$BTMON_PID" 2>/dev/null; then
        echo "btmon s'est arrete immediatement :"
        head -n 5 "$OUT/btmon_$1.txt"
        BTMON_PID=
        return 1
    fi
    return 0
}

# Le texte decode par btmon peut peser plusieurs Mo : on n'en garde que l'en-tete.
end_btmon() {
    stop_btmon
    if [ -f "$OUT/$1.btsnoop" ]; then
        echo "capture : $(wc -c < "$OUT/$1.btsnoop") octets dans $OUT/$1.btsnoop"
    fi
    if [ -f "$OUT/btmon_$1.txt" ]; then
        echo "btmon : $(head -n 1 "$OUT/btmon_$1.txt")"
        rm -f "$OUT/btmon_$1.txt"
    fi
}

cleanup() {
    # D'abord remettre le reglage des capteurs Bluetooth, sans rien afficher (la sortie
    # peut etre fermee si la session SSH est tombee)
    if [ -n "$BLE_RESTORE" ]; then
        python3 "$HELPER" setting /Settings/Services/BleSensors "$BLE_RESTORE" >/dev/null 2>&1
        BLE_RESTORE=
    fi
    if [ -n "$SLEEP_PID" ]; then
        kill "$SLEEP_PID" 2>/dev/null
        SLEEP_PID=
    fi
    stop_btmon
    if [ -n "$HCIMON_PID" ]; then
        kill -TERM "$HCIMON_PID" 2>/dev/null
        HCIMON_PID=
    fi
}

platform() {
    section "1) PLATEFORME"
    VENUS_VERSION=$(head -n 1 /opt/victronenergy/version 2>/dev/null)
    VENUS_BUILD=$(sed -n 2p /opt/victronenergy/version 2>/dev/null)
    MACHINE=$(cat /etc/venus/machine 2>/dev/null)
    echo "venus version : ${VENUS_VERSION:-?} (build ${VENUS_BUILD:-?})"
    echo "machine       : ${MACHINE:-?}"
    echo "noyau         : $(uname -r) $(uname -m)"
    echo "python3       : $(python3 -V 2>&1)"
    echo "setuphelper   : $(cat /data/SetupHelper/version 2>/dev/null || echo ABSENT)"
    echo "date (UTC)    : $(date -u '+%Y-%m-%d %H:%M:%S')"
    if [ "$(date -u +%Y)" -lt 2025 ]; then
        echo "ATTENTION : horloge fausse (horodatages des captures non significatifs)"
    fi
    echo "uptime        : $(cut -d' ' -f1 /proc/uptime) s"
}

bt_system() {
    section "3) BLUETOOTH : OUTILS ET CONTROLEUR"
    BLUETOOTHD=
    for p in /usr/libexec/bluetooth/bluetoothd /usr/lib/bluetooth/bluetoothd /usr/sbin/bluetoothd /usr/bin/bluetoothd; do
        if [ -x "$p" ]; then BLUETOOTHD=$p; break; fi
    done
    if [ -n "$BLUETOOTHD" ]; then
        echo "bluetoothd    : $BLUETOOTHD version $(run_to 3 "$BLUETOOTHD" --version 2>&1 | head -n 1)"
    else
        echo "bluetoothd    : introuvable"
    fi
    BTMON=$(command -v btmon 2>/dev/null)
    if [ -n "$BTMON" ]; then
        echo "btmon         : $BTMON version $(run_to 3 "$BTMON" --version 2>&1 | head -n 1)"
    else
        echo "btmon         : ABSENT (les phases 7 et 8 se limiteront au cote D-Bus)"
    fi
    for b in hciconfig btmgmt bluetoothctl hcitool hcidump; do
        printf '%-13s : %s\n' "$b" "$(command -v "$b" 2>/dev/null || echo absent)"
    done
    echo "--- paquets (opkg) ---"
    if have opkg; then
        opkg list-installed 2>/dev/null \
            | grep -i -E '^(bluez[0-9a-z-]*|libcrypto[0-9a-z.-]*|openssl[0-9a-z-]*|python3-(dbus|pygobject|pycryptodome|pycryptodomex|cryptography|construct)) ' \
            || echo "aucun paquet correspondant"
    else
        echo "opkg absent"
    fi
    echo "--- controleurs (/sys/class/bluetooth) ---"
    ls /sys/class/bluetooth 2>/dev/null || echo "aucun"
    if have hciconfig; then
        run_to 5 hciconfig -a hci0 2>&1
    fi
    echo "--- rfkill ---"
    rf=0
    for r in /sys/class/rfkill/rfkill*; do
        [ -e "$r/type" ] || continue
        rf=1
        echo "$(basename "$r") : type=$(cat "$r/type") nom=$(cat "$r/name" 2>/dev/null) soft=$(cat "$r/soft" 2>/dev/null) hard=$(cat "$r/hard" 2>/dev/null)"
    done
    [ $rf = 1 ] || echo "aucun"
    echo "--- dmesg (bluetooth, 15 dernieres lignes) ---"
    dmesg 2>/dev/null | grep -i -E 'bluetooth|hci_uart|btbcm|hci0' | tail -n 15
    echo "--- /etc/bluetooth/main.conf (lignes actives) ---"
    if [ -f /etc/bluetooth/main.conf ]; then
        grep -v -E '^[[:space:]]*(#|$)' /etc/bluetooth/main.conf || echo "(aucune ligne active)"
    else
        echo "absent"
    fi
}

venus_bt_services() {
    section "4) SERVICES BLUETOOTH DE VENUS"
    echo "--- services runit ---"
    found=0
    for s in /service/*; do
        n=$(basename "$s")
        case "$n" in
            *[Bb]luetooth*|*bluez*|*-ble*|*ble-*|*_ble*|*ble_*|*vesmart*|*hci*)
                found=1
                svstat "$s" 2>/dev/null || echo "$s (svstat impossible)"
                [ -f "$s/down" ] && echo "    (fichier down present)"
                ;;
        esac
    done
    [ $found = 1 ] || echo "aucun service runit lie au Bluetooth"
    echo "--- processus ---"
    ps 2>/dev/null | grep -i -E 'bluetooth|bluez|vesmart|[-_/]ble|ble[-_]|btmon|hci[0-9_u]' \
        | grep -v -E 'grep|venus-ble-diag' \
        || echo "aucun"
    echo "--- paquets tiers BLE dans /data ---"
    ls -d /data/*[Bb][Ll][Ee]* /data/apps/*[Bb][Ll][Ee]* 2>/dev/null \
        || echo "aucun"
}

capture_passive() {
    section "7) ECOUTE PASSIVE btmon (${DUR} s, aucun scan lance par le script)"
    if [ -z "$BTMON" ]; then
        echo "btmon absent : phase sautee"
        return
    fi
    start_btmon passive || return
    # Sonde en parallele : lecture du meme canal moniteur HCI directement depuis Python
    python3 -u "$HELPER" hcimon passive "$DUR" > "$OUT/hcimon.txt" 2>&1 &
    HCIMON_PID=$!
    echo "capture en cours (${DUR} s)..."
    pause "$DUR"
    wait "$HCIMON_PID" 2>/dev/null
    HCIMON_PID=
    end_btmon passive
    cat "$OUT/hcimon.txt"
    rm -f "$OUT/hcimon.txt"
}

capture_discovery() {
    section "8) DECOUVERTE BlueZ (SetDiscoveryFilter + StartDiscovery, ${DUR} s)"
    if [ "$DO_DISCOVERY" != 1 ]; then
        echo "sautee (--passive-only)"
        return
    fi
    if [ -n "$BTMON" ]; then
        start_btmon discovery || echo "poursuite sans btmon (cote D-Bus seulement)"
    fi
    python3 -u "$HELPER" discover "$DUR"
    end_btmon discovery
}

list_files() {
    section "FICHIERS PRODUITS"
    ls -l "$OUT"
    echo
    echo "Me renvoyer : $OUT/diag.log"
    echo "Rapatrier le dossier depuis le PC (PowerShell) :"
    echo "    scp -r root@<ip-tailscale>:$OUT ."
}

set_traps() {
    trap cleanup EXIT
    trap 'echo; echo "interrompu"; exit 130' INT TERM
    # Coupure de la session SSH (4G) : sans ces deux pieges, btmon resterait lance indefiniment
    trap 'exit 129' HUP
    trap 'exit 141' PIPE
}

banner() {
    echo "================================================================"
    echo " venus-ble-diag $1  $(date '+%Y-%m-%d %H:%M:%S')  phases de ${DUR} s  sortie $OUT"
    echo "================================================================"
}

# ------------------------------------------------------- mode --advmon ----

# start_hcimon LIBELLE : lecteur Python du canal moniteur HCI, jusqu'a stop_hcimon
start_hcimon() {
    python3 -u "$HELPER" hcimon "$1" 3600 > "$OUT/hcimon_$1.txt" 2>&1 &
    HCIMON_PID=$!
}

stop_hcimon() {
    [ -n "$HCIMON_PID" ] || return 0
    kill -TERM "$HCIMON_PID" 2>/dev/null
    wait "$HCIMON_PID" 2>/dev/null
    HCIMON_PID=
    cat "$OUT/hcimon_$1.txt" 2>/dev/null
    rm -f "$OUT/hcimon_$1.txt"
}

ble_sensors_state() {
    echo "BleSensors=$(python3 "$HELPER" setting /Settings/Services/BleSensors 2>/dev/null) ContinuousScan=$(python3 "$HELPER" setting /Settings/BleSensors/ContinuousScan 2>/dev/null) ; $(svstat /service/dbus-ble-sensors 2>/dev/null)"
}

# Mode --sensors : capteurs Bluetooth de Venus seuls, sans AdvertisementMonitor (qui perturbe vesmart-server)
main_sensors() {
    set_traps
    banner "--sensors"
    context_advmon
    section "2) CAPTEURS BLUETOOTH DE VENUS SEULS (${DUR} s)"
    ble_old=$(python3 "$HELPER" setting /Settings/Services/BleSensors 2>/dev/null)
    case "$ble_old" in
        0|1) ;;
        *) echo "reglage BleSensors illisible ('$ble_old') : test annule"; list_files; return ;;
    esac
    python3 "$HELPER" names > "$OUT/services_avant.txt" 2>/dev/null
    [ -n "$BTMON" ] && start_btmon blesensors
    start_hcimon blesensors
    if [ "$ble_old" != 1 ]; then
        BLE_RESTORE=$ble_old
        echo "activation : BleSensors=$(python3 "$HELPER" setting /Settings/Services/BleSensors 1)"
    fi
    pause 5
    echo "apres 5 s : $(ble_sensors_state)"
    left=$((DUR - 5))
    while [ "$left" -gt 0 ]; do           # un point d'etat par minute
        step=60
        [ "$left" -lt 60 ] && step=$left
        pause "$step"
        left=$((left - step))
        echo "+$((DUR - left)) s : $(svstat /service/dbus-ble-sensors 2>/dev/null)"
    done
    stop_hcimon blesensors
    end_btmon blesensors
    python3 "$HELPER" names > "$OUT/services_apres.txt" 2>/dev/null
    echo "--- services D-Bus apparus :"
    grep -vxF -f "$OUT/services_avant.txt" "$OUT/services_apres.txt" || echo "aucun"
    if [ -n "$BLE_RESTORE" ]; then
        echo "restauration : BleSensors=$(python3 "$HELPER" setting /Settings/Services/BleSensors "$BLE_RESTORE")"
        BLE_RESTORE=
        pause 5
        echo "apres 5 s : $(ble_sensors_state)"
    fi
    section "3) ANALYSE"
    python3 -u "$HELPER" analyze blesensors "$OUT/blesensors.btsnoop"
    section "4) SYNTHESE"
    python3 -u "$HELPER" summary2
    list_files
}

context_advmon() {
    section "1) CONTEXTE"
    echo "venus : $(head -n 1 /opt/victronenergy/version 2>/dev/null)  noyau $(uname -r)  $(python3 -V 2>&1)"
    set -- $(pidof bluetoothd 2>/dev/null)
    if [ -n "$1" ]; then
        echo "bluetoothd : $(tr '\0' ' ' < "/proc/$1/cmdline")"
        cfg=$(tr '\0' '\n' < "/proc/$1/cmdline" | awk 'f { print; exit } $0 == "-f" { f = 1 }')
        if [ -n "$cfg" ] && [ -f "$cfg" ]; then
            echo "--- $cfg (lignes actives)"
            grep -v -E '^[[:space:]]*(#|$)' "$cfg"
        fi
    else
        echo "bluetoothd : NON LANCE"
    fi
    echo "capteurs Bluetooth : $(ble_sensors_state)"
    BTMON=$(command -v btmon 2>/dev/null)
    echo "btmon : ${BTMON:-ABSENT}"
}

# phase_monitor LIBELLE : AdvertisementMonitor + btmon + socket Python en parallele
phase_monitor() {
    [ -n "$BTMON" ] && start_btmon "$1"
    start_hcimon "$1"
    python3 -u "$HELPER" advmon "$1" "$DUR"
    stop_hcimon "$1"
    end_btmon "$1"
}

phase_ble_sensors() {
    section "3) PHASES S1/S2 : capteurs Bluetooth de Venus (dbus-ble-sensors, scan en HCI brut)"
    ble_old=$(python3 "$HELPER" setting /Settings/Services/BleSensors 2>/dev/null)
    case "$ble_old" in
        0|1) ;;
        *) echo "reglage BleSensors illisible ('$ble_old') : phases sautees"; return ;;
    esac
    echo "etat initial : $(ble_sensors_state)"
    python3 "$HELPER" names > "$OUT/services_avant.txt" 2>/dev/null
    s1=$((DUR * 2))
    echo "--- S1 : capteurs seuls, ${s1} s"
    [ -n "$BTMON" ] && start_btmon blesensors
    start_hcimon blesensors
    if [ "$ble_old" != 1 ]; then
        BLE_RESTORE=$ble_old
        echo "activation : BleSensors=$(python3 "$HELPER" setting /Settings/Services/BleSensors 1)"
    fi
    pause 5
    echo "apres 5 s : $(ble_sensors_state)"
    pause $((s1 - 5))
    stop_hcimon blesensors
    end_btmon blesensors
    echo "--- S2 : capteurs + AdvertisementMonitor, ${DUR} s de mesure"
    phase_monitor mixed
    python3 "$HELPER" names > "$OUT/services_apres.txt" 2>/dev/null
    echo "--- services D-Bus apparus pendant S1/S2 :"
    grep -vxF -f "$OUT/services_avant.txt" "$OUT/services_apres.txt" || echo "aucun"
    if [ -n "$BLE_RESTORE" ]; then
        echo "restauration : BleSensors=$(python3 "$HELPER" setting /Settings/Services/BleSensors "$BLE_RESTORE")"
        BLE_RESTORE=
        pause 5
        echo "apres 5 s : $(ble_sensors_state)"
    fi
}

main_advmon() {
    set_traps
    banner "--advmon"
    context_advmon
    section "2) PHASE M : AdvertisementMonitor seul (scan passif BlueZ, ${DUR} s de mesure)"
    phase_monitor advmon
    if [ "$DO_BLESENSORS" = 1 ]; then
        phase_ble_sensors
    else
        section "3) PHASES S1/S2"
        echo "sautees (ajouter --ble-sensors)"
    fi
    section "4) ANALYSE DES CAPTURES"
    python3 -u "$HELPER" analyze advmon "$OUT/advmon.btsnoop" blesensors "$OUT/blesensors.btsnoop" \
        mixed "$OUT/mixed.btsnoop"
    section "5) SYNTHESE"
    python3 -u "$HELPER" summary2
    list_files
}

# ---------------------------------------------------- mode diagnostic ----

main() {
    set_traps
    banner ""

    platform

    section "2) PYTHON ET BIBLIOTHEQUES"
    python3 -u "$HELPER" libs

    bt_system
    venus_bt_services

    section "5) BLUEZ SUR LE D-BUS SYSTEME"
    python3 -u "$HELPER" bluez

    section "6) VENUS : APPAREILS ET REGLAGES"
    python3 -u "$HELPER" venus

    capture_passive
    capture_discovery

    section "9) ANALYSE DES CAPTURES"
    python3 -u "$HELPER" analyze passive "$OUT/passive.btsnoop" discovery "$OUT/discovery.btsnoop"

    section "10) SYNTHESE"
    DIAG_VENUS="${VENUS_VERSION:-?}" DIAG_MACHINE="${MACHINE:-?}" python3 -u "$HELPER" summary

    list_files
}

# tee ignore SIGINT : les messages d'interruption arrivent quand meme dans diag.log
if [ "$MODE" = advmon ]; then
    main_advmon 2>&1 | (trap '' INT; tee "$OUT/diag.log")
elif [ "$MODE" = sensors ]; then
    main_sensors 2>&1 | (trap '' INT; tee "$OUT/diag.log")
else
    main 2>&1 | (trap '' INT; tee "$OUT/diag.log")
fi
