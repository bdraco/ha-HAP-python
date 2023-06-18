"""This module contains constants used by other modules."""
MAJOR_VERSION = 4
MINOR_VERSION = 7
PATCH_VERSION = 0
__short_version__ = f"{MAJOR_VERSION}.{MINOR_VERSION}"
__version__ = f"{__short_version__}.{PATCH_VERSION}"
REQUIRED_PYTHON_VER = (3, 7)

BASE_UUID = "-0000-1000-8000-0026BB765291"

# ### Misc ###
STANDALONE_AID = 1  # Standalone accessory ID (i.e. not bridged)

# ### Default values ###
DEFAULT_CONFIG_VERSION = 1
DEFAULT_PORT = 51827

# ### Configuration version ###
MAX_CONFIG_VERSION = 65535

# ### CATEGORY values ###
# Category is a hint to iOS clients about what "type" of Accessory this
# represents, for UI only.
CATEGORY_OTHER = 1
CATEGORY_BRIDGE = 2
CATEGORY_FAN = 3
CATEGORY_GARAGE_DOOR_OPENER = 4
CATEGORY_LIGHTBULB = 5
CATEGORY_DOOR_LOCK = 6
CATEGORY_OUTLET = 7
CATEGORY_SWITCH = 8
CATEGORY_THERMOSTAT = 9
CATEGORY_SENSOR = 10
CATEGORY_ALARM_SYSTEM = 11
CATEGORY_DOOR = 12
CATEGORY_WINDOW = 13
CATEGORY_WINDOW_COVERING = 14
CATEGORY_PROGRAMMABLE_SWITCH = 15
CATEGORY_RANGE_EXTENDER = 16
CATEGORY_CAMERA = 17
CATEGORY_VIDEO_DOOR_BELL = 18
CATEGORY_AIR_PURIFIER = 19
CATEGORY_HEATER = 20
CATEGORY_AIR_CONDITIONER = 21
CATEGORY_HUMIDIFIER = 22
CATEGORY_DEHUMIDIFIER = 23
CATEGORY_SPEAKER = 26
CATEGORY_SPRINKLER = 28
CATEGORY_FAUCET = 29
CATEGORY_SHOWER_HEAD = 30
CATEGORY_TELEVISION = 31
CATEGORY_TARGET_CONTROLLER = 32  # Remote Controller


# ### HAP Permissions ###
HAP_PERMISSION_HIDDEN = "hd"
HAP_PERMISSION_NOTIFY = "ev"
HAP_PERMISSION_READ = "pr"
HAP_PERMISSION_WRITE = "pw"
HAP_PERMISSION_WRITE_RESPONSE = "wr"


# ### HAP representation ###
HAP_REPR_ACCS = "accessories"
HAP_REPR_AID = "aid"
HAP_REPR_CHARS = "characteristics"
HAP_REPR_DESC = "description"
HAP_REPR_FORMAT = "format"
HAP_REPR_IID = "iid"
HAP_REPR_MAX_LEN = "maxLen"
HAP_REPR_PERM = "perms"
HAP_REPR_PID = "pid"
HAP_REPR_PRIMARY = "primary"
HAP_REPR_SERVICES = "services"
HAP_REPR_LINKED = "linked"
HAP_REPR_STATUS = "status"
HAP_REPR_TTL = "ttl"
HAP_REPR_TYPE = "type"
HAP_REPR_VALUE = "value"
HAP_REPR_VALID_VALUES = "valid-values"

HAP_PROTOCOL_VERSION = "01.01.00"
HAP_PROTOCOL_SHORT_VERSION = "1.1"


# Status codes for underlying HAP calls
class HAP_SERVER_STATUS:
    SUCCESS = 0
    INSUFFICIENT_PRIVILEGES = -70401
    SERVICE_COMMUNICATION_FAILURE = -70402
    RESOURCE_BUSY = -70403
    READ_ONLY_CHARACTERISTIC = -70404
    WRITE_ONLY_CHARACTERISTIC = -70405
    NOTIFICATION_NOT_SUPPORTED = -70406
    OUT_OF_RESOURCE = -70407
    OPERATION_TIMED_OUT = -70408
    RESOURCE_DOES_NOT_EXIST = -70409
    INVALID_VALUE_IN_REQUEST = -70410
    INSUFFICIENT_AUTHORIZATION = -70411


class HAP_PERMISSIONS:
    USER = b"\x00"
    ADMIN = b"\x01"


# Client properties
CLIENT_PROP_PERMS = "permissions"
