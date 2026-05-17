/**
 * ================================================================
 * Rex IoT Security Framework — C++ Core
 * Rex Cybersecurity Project
 * ================================================================
 * File: iot_packet.hpp
 * Description: Core data structures for IoT sensor packets,
 *              security alerts, and device registry entries.
 *              Designed for embedded gateway deployment.
 * ================================================================
 */

#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <chrono>
#include <map>

namespace Rex {
namespace Core {

// ── Sensor Types ──────────────────────────────────────────────
enum class SensorType : uint8_t {
    SOIL_MOISTURE     = 0x01,
    TEMPERATURE       = 0x02,
    HUMIDITY          = 0x03,
    IRRIGATION_VALVE  = 0x04,
    WEATHER_STATION   = 0x05,
    PESTICIDE_DRONE   = 0x06,
    LIVESTOCK_TRACKER = 0x07,
    UNKNOWN           = 0xFF,
};

// ── Threat Levels ─────────────────────────────────────────────
enum class ThreatLevel : uint8_t {
    NONE     = 0,
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4,
};

inline const char* threatLevelName(ThreatLevel lvl) {
    switch (lvl) {
        case ThreatLevel::NONE:     return "NONE";
        case ThreatLevel::LOW:      return "LOW";
        case ThreatLevel::MEDIUM:   return "MEDIUM";
        case ThreatLevel::HIGH:     return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default:                    return "UNKNOWN";
    }
}

// ── Packet Status ─────────────────────────────────────────────
enum class PacketStatus : uint8_t {
    OK           = 0,
    AUTH_FAILED  = 1,
    RATE_LIMITED = 2,
    OUT_OF_RANGE = 3,
    ANOMALOUS    = 4,
    REPLAYED     = 5,
};

// ── IoT Sensor Packet ─────────────────────────────────────────
struct IoTPacket {
    char        device_id[32];       // Unique device identifier
    char        region[32];          // Deployment zone/region
    char        location[64];        // Farm/site description
    SensorType  sensor_type;
    float       value;               // Sensor reading
    uint64_t    timestamp_ms;        // Unix time in milliseconds
    uint32_t    sequence_number;     // For replay attack detection
    uint8_t     hmac_sha256[32];     // HMAC-SHA256 signature (32 bytes)
    uint8_t     flags;               // Bit flags (encrypted, compressed, etc.)

    static constexpr size_t SERIALIZED_SIZE =
        sizeof(device_id) + sizeof(region) + sizeof(location) +
        sizeof(sensor_type) + sizeof(value) + sizeof(timestamp_ms) +
        sizeof(sequence_number) + sizeof(hmac_sha256) + sizeof(flags);
};

// ── Security Alert ────────────────────────────────────────────
struct SecurityAlert {
    uint32_t    alert_id;
    char        device_id[32];
    ThreatLevel threat_level;
    char        description[256];
    char        action_taken[128];
    uint64_t    timestamp_ms;
    char        region[32];
};

// ── Device Registry Entry ─────────────────────────────────────
struct DeviceEntry {
    char        device_id[32];
    char        region[32];
    SensorType  sensor_type;
    float       value_min;
    float       value_max;
    bool        is_trusted;
    uint32_t    last_sequence;        // For replay detection
    uint64_t    last_seen_ms;
    uint8_t     session_key[32];      // Per-device session key (AES-256)
};

// ── Default Region Codes ──────────────────────────────────────
const std::map<std::string, uint8_t> DEFAULT_REGIONS = {
    {"Zone-A",      0x01}, {"Zone-B",            0x02},
    {"Zone-C",      0x03}, {"Zone-D",            0x04},
    {"Zone-E",      0x05}, {"Zone-F",            0x06},
    {"Zone-G",      0x07}, {"Zone-H",            0x08},
    {"Zone-I",      0x09}, {"Zone-J",            0x0A},
    {"Zone-K",      0x0B},
};

}  // namespace Core
}  // namespace Rex
