import ctypes
import os
import sys
import logging
from enum import Enum
from typing import Optional, Union

logger = logging.getLogger("Rex.Core")


class ProcessResult(Enum):
    OK = 0
    AUTH_FAIL = 1
    RATE_LIMITED = 2
    OUT_OF_RANGE = 3
    REPLAY = 4
    LIBRARY_LOAD_ERROR = 99


class CppGatewayBridge:
    """
    ctypes-based Python wrapper around the Rex C++ Core Engine.
    Speeds up critical network packet operations (HMAC, sliding-window rate limiting,
    freshness validation) to C++ speeds.
    """

    def __init__(self, lib_path: Optional[str] = None):
        self._lib = None
        self._loaded = False
        self._load_library(lib_path)

    def _load_library(self, lib_path: Optional[str] = None):
        if lib_path is None:
            # Resolve relative to package directory: rex/core/lib/
            base_dir = os.path.dirname(os.path.abspath(__file__))
            if sys.platform == "win32":
                filename = "rex_gateway.dll"
            elif sys.platform == "darwin":
                filename = "librex_gateway.dylib"
            else:
                filename = "librex_gateway.so"
            lib_path = os.path.join(base_dir, "lib", filename)

        if not os.path.exists(lib_path):
            logger.warning(
                f"C++ core library not found at: {lib_path}. Falling back to pure Python mode."
            )
            return

        try:
            # Load the library with winmode=0 on Windows to avoid security loading constraints
            if sys.platform == "win32" and sys.version_info >= (3, 8):
                self._lib = ctypes.CDLL(lib_path, winmode=0)
            else:
                self._lib = ctypes.CDLL(lib_path)

            # Define function arguments and return types
            self._lib.validate_iot_packet.argtypes = [
                ctypes.c_char_p,               # device_id
                ctypes.c_char_p,               # region/zone
                ctypes.c_char_p,               # location
                ctypes.c_uint8,                # sensor_type
                ctypes.c_float,                # value
                ctypes.c_uint64,               # timestamp_ms
                ctypes.c_uint32,               # sequence_number
                ctypes.c_uint8,                # flags
                ctypes.POINTER(ctypes.c_uint8)  # hmac_sha256 signature (32 bytes)
            ]
            self._lib.validate_iot_packet.restype = ctypes.c_int
            self._loaded = True
            logger.info("Rex C++ Core Engine successfully loaded and bound.")
        except Exception as e:
            logger.error(f"Failed to load C++ shared library: {e}. Pure Python fallback will be used.")

    @property
    def is_available(self) -> bool:
        """True if the compiled C++ library was loaded successfully."""
        return self._loaded

    def validate_packet(
        self,
        device_id: str,
        region: str,
        location: str,
        sensor_type: int,
        value: float,
        timestamp_ms: int,
        sequence_number: int,
        flags: int = 0,
        hmac_bytes: Optional[Union[bytes, list]] = None
    ) -> ProcessResult:
        """
        Pass a packet to the C++ core engine for extreme-performance verification.
        """
        if not self._loaded or self._lib is None:
            return ProcessResult.LIBRARY_LOAD_ERROR

        # Convert strings to bytes for C interface
        dev_bytes = device_id.encode("utf-8")
        reg_bytes = region.encode("utf-8")
        loc_bytes = location.encode("utf-8")

        # Set up HMAC pointer
        hmac_arr = (ctypes.c_uint8 * 32)()
        if hmac_bytes:
            if len(hmac_bytes) != 32:
                logger.error(f"HMAC must be exactly 32 bytes, got {len(hmac_bytes)}")
                return ProcessResult.AUTH_FAIL
            for i, b in enumerate(hmac_bytes):
                hmac_arr[i] = b

        try:
            res_code = self._lib.validate_iot_packet(
                dev_bytes,
                reg_bytes,
                loc_bytes,
                ctypes.c_uint8(sensor_type),
                ctypes.c_float(value),
                ctypes.c_uint64(timestamp_ms),
                ctypes.c_uint32(sequence_number),
                ctypes.c_uint8(flags),
                hmac_arr
            )
            return ProcessResult(res_code)
        except ValueError:
            logger.error(f"C++ engine returned invalid code")
            return ProcessResult.AUTH_FAIL
        except Exception as e:
            logger.error(f"Error during C++ packet validation: {e}")
            return ProcessResult.AUTH_FAIL
