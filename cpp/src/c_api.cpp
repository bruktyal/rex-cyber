#include "../include/iot_packet.hpp"
#include <cstdint>
#include <cstring>

using namespace Rex::Core;

// Forward declare the existing process_packet function from gateway_security.cpp
// Note: We'll need to modify gateway_security.cpp slightly to remove `static` from process_packet 
// or implement a wrapper here that does the same logic. Let's just implement the bridge here.

// Re-declare ProcessResult so the C API can return it as int
enum class ProcessResult : uint8_t {
    OK           = 0,
    AUTH_FAIL    = 1,
    RATE_LIMITED = 2,
    OUT_OF_RANGE = 3,
    REPLAY       = 4,
};

// Declare the function from gateway_security.cpp (it's a C++ function)
ProcessResult process_packet(const IoTPacket& pkt);

// We will expose this function to Python
extern "C" {

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

    // Expose a function to validate a packet
    // Python will pass strings and primitive types
    EXPORT int validate_iot_packet(
        const char* device_id,
        const char* region,
        const char* location,
        uint8_t sensor_type,
        float value,
        uint64_t timestamp_ms,
        uint32_t sequence_number,
        uint8_t flags,
        const uint8_t* hmac_sha256
    ) {
        IoTPacket pkt = {};
        strncpy(pkt.device_id, device_id, 31);
        strncpy(pkt.region, region, 31);
        strncpy(pkt.location, location, 63);
        pkt.sensor_type = static_cast<SensorType>(sensor_type);
        pkt.value = value;
        pkt.timestamp_ms = timestamp_ms;
        pkt.sequence_number = sequence_number;
        pkt.flags = flags;
        
        if (hmac_sha256) {
            memcpy(pkt.hmac_sha256, hmac_sha256, 32);
        }

        return static_cast<int>(process_packet(pkt));
    }
}
