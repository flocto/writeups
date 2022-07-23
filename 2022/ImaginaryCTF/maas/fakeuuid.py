from uuid import *

import os
import sys

from enum import Enum

int_ = int      # The built-in int type
bytes_ = bytes  # The built-in bytes type

try:
    import _uuid
    _generate_time_safe = getattr(_uuid, "generate_time_safe", None)
    _UuidCreate = getattr(_uuid, "UuidCreate", None)
    _has_uuid_generate_time_safe = _uuid.has_uuid_generate_time_safe
except ImportError:
    _uuid = None
    _generate_time_safe = None
    _UuidCreate = None
    _has_uuid_generate_time_safe = None

__author__ = 'Ka-Ping Yee <ping@zesty.ca>'

# The recognized platforms - known behaviors
if sys.platform in ('win32', 'darwin'):
    _AIX = _LINUX = False
else:
    import platform
    _platform_system = platform.system()
    _AIX     = _platform_system == 'AIX'
    _LINUX   = _platform_system == 'Linux'

_MAC_DELIM = b':'
_MAC_OMITS_LEADING_ZEROES = False
if _AIX:
    _MAC_DELIM = b'.'
    _MAC_OMITS_LEADING_ZEROES = True

RESERVED_NCS, RFC_4122, RESERVED_MICROSOFT, RESERVED_FUTURE = [
    'reserved for NCS compatibility', 'specified in RFC 4122',
    'reserved for Microsoft compatibility', 'reserved for future definition']

_last_timestamp = None


def fakeuuid1(timing=None, node=None, clock_seq=None):
    """Generate a UUID from a host ID, sequence number, and the current time.
    If 'node' is not given, getnode() is used to obtain the hardware
    address.  If 'clock_seq' is given, it is used as the sequence number;
    otherwise a random 14-bit sequence number is chosen."""

    # When the system provides a version-1 UUID generator, use it (but don't
    # use UuidCreate here because its UUIDs don't conform to RFC 4122).
    # if _generate_time_safe is not None and node is clock_seq is None:
    #     uuid_time, safely_generated = _generate_time_safe()
    #     try:
    #         is_safe = SafeUUID(safely_generated)
    #     except ValueError:
    #         is_safe = SafeUUID.unknown
    #     return UUID(bytes=uuid_time, is_safe=is_safe)

    import time
    nanoseconds = time.time_ns() if timing is None else timing
    timestamp = nanoseconds // 100 + 0x01b21dd213814000
    if clock_seq is None:
        import random
        clock_seq = random.getrandbits(14) # instead of stable storage
    time_low = timestamp & 0xffffffff
    time_mid = (timestamp >> 32) & 0xffff
    time_hi_version = (timestamp >> 48) & 0x0fff
    clock_seq_low = clock_seq & 0xff
    clock_seq_hi_variant = (clock_seq >> 8) & 0x3f
    if node is None:
        node = getnode()
    return UUID(fields=(time_low, time_mid, time_hi_version,
                        clock_seq_hi_variant, clock_seq_low, node), version=1)