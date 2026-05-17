/**
 * ================================================================
 * Rex IoT Security Framework — C++ Core
 * Rex Cybersecurity Project
 * ================================================================
 * File: gateway_security.cpp
 * Description: Embedded gateway security processor.
 *              Runs on Raspberry Pi / industrial gateways deployed
 *              at edge field sites. Handles:
 *              - HMAC packet authentication
 *              - Replay attack prevention (sequence numbers)
 *              - Device registry management
 *              - Rate limiting per device
 *              - Security event logging
 * ================================================================
 */

#include "../include/iot_packet.hpp"
#include "../include/hmac_auth.hpp"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <unordered_map>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>

using namespace Rex::Core;
using namespace Rex::Crypto;

// ── Constants ─────────────────────────────────────────────────
static constexpr uint32_t MAX_DEVICES        = 256;
static constexpr uint32_t RATE_LIMIT_PPS     = 10;   // packets per second per device
static constexpr uint64_t REPLAY_WINDOW_MS   = 30000; // 30-second replay window
static constexpr size_t   ALERT_BUFFER_SIZE  = 1024;

// Rex shared HMAC key (in production: loaded from secure HSM)
static const uint8_t REX_MASTER_KEY[32] = {
    0xE5, 0x1A, 0x4B, 0x8C, 0xD2, 0x6F, 0x93, 0x07,
    0xAB, 0x3E, 0x12, 0x5D, 0x74, 0xC8, 0x29, 0xF6,
    0x0D, 0xE7, 0x41, 0x9A, 0xBB, 0x53, 0x6E, 0x28,
    0x14, 0x97, 0xC0, 0x35, 0xF2, 0x8D, 0x4A, 0x61,
};

// ── Utility: Get current time in milliseconds ─────────────────
static uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()
    );
}

// ── Security Event Log ────────────────────────────────────────
struct SecurityEvent {
    uint64_t    timestamp_ms;
    ThreatLevel threat_level;
    char        device_id[32];
    char        message[256];
};

static SecurityEvent g_event_log[ALERT_BUFFER_SIZE];
static size_t        g_event_count = 0;

static void log_event(ThreatLevel level, const char* device_id, const char* msg) {
    if (g_event_count >= ALERT_BUFFER_SIZE) return;
    SecurityEvent& ev = g_event_log[g_event_count++];
    ev.timestamp_ms = now_ms();
    ev.threat_level = level;
    strncpy(ev.device_id, device_id, 31);
    ev.device_id[31] = '\0';
    strncpy(ev.message, msg, 255);
    ev.message[255] = '\0';

    const char* lvl = threatLevelName(level);
    char ts[32];
    time_t t = static_cast<time_t>(ev.timestamp_ms / 1000);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    fprintf(stderr, "[%s] [%s] %s — %s\n", ts, lvl, device_id, msg);
}

// ── Rate Limiter ──────────────────────────────────────────────
struct RateLimitEntry {
    uint64_t window_start_ms;
    uint32_t packet_count;
};

static std::unordered_map<std::string, RateLimitEntry> g_rate_limits;

static bool rate_check(const char* device_id) {
    uint64_t now = now_ms();
    auto& entry = g_rate_limits[device_id];
    if (now - entry.window_start_ms >= 1000) {
        entry.window_start_ms = now;
        entry.packet_count = 0;
    }
    entry.packet_count++;
    return entry.packet_count <= RATE_LIMIT_PPS;
}

// ── Replay Attack Detector ────────────────────────────────────
static std::unordered_map<std::string, uint32_t> g_last_seq;
static std::unordered_map<std::string, uint64_t> g_last_ts;

static bool replay_check(const IoTPacket& pkt) {
    std::string dev(pkt.device_id);
    uint64_t now = now_ms();

    // Check timestamp freshness
    if (g_last_ts.count(dev)) {
        int64_t delta = static_cast<int64_t>(now) - static_cast<int64_t>(pkt.timestamp_ms);
        if (delta < 0) delta = -delta;
        if (static_cast<uint64_t>(delta) > REPLAY_WINDOW_MS) {
            log_event(ThreatLevel::HIGH, pkt.device_id,
                      "Replay attack: stale timestamp");
            return false;
        }
    }

    // Check sequence number monotonicity
    if (g_last_seq.count(dev)) {
        if (pkt.sequence_number <= g_last_seq[dev]) {
            log_event(ThreatLevel::HIGH, pkt.device_id,
                      "Replay attack: sequence number regression");
            return false;
        }
    }

    g_last_seq[dev] = pkt.sequence_number;
    g_last_ts[dev]  = now;
    return true;
}

// ── Value Range Validator ─────────────────────────────────────
static bool range_check(const IoTPacket& pkt) {
    float v = pkt.value;
    bool ok = true;
    switch (pkt.sensor_type) {
        case SensorType::SOIL_MOISTURE:    ok = (v >= 0.0f   && v <= 100.0f); break;
        case SensorType::TEMPERATURE:      ok = (v >= -10.0f && v <= 60.0f);  break;
        case SensorType::HUMIDITY:         ok = (v >= 0.0f   && v <= 100.0f); break;
        case SensorType::IRRIGATION_VALVE: ok = (v == 0.0f   || v == 1.0f);   break;
        default: break;
    }
    if (!ok) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Out-of-range value: %.2f for sensor type 0x%02X",
                 v, static_cast<uint8_t>(pkt.sensor_type));
        log_event(ThreatLevel::MEDIUM, pkt.device_id, msg);
    }
    return ok;
}

// ── HMAC Authenticator ────────────────────────────────────────
static bool auth_check(const IoTPacket& pkt) {
    // Build payload for HMAC (all fields except the hmac itself)
    uint8_t payload[IoTPacket::SERIALIZED_SIZE - 32];
    size_t off = 0;
    memcpy(payload + off, pkt.device_id,      32); off += 32;
    memcpy(payload + off, pkt.region,         32); off += 32;
    memcpy(payload + off, pkt.location,       64); off += 64;
    memcpy(payload + off, &pkt.sensor_type,   1);  off += 1;
    memcpy(payload + off, &pkt.value,         4);  off += 4;
    memcpy(payload + off, &pkt.timestamp_ms,  8);  off += 8;
    memcpy(payload + off, &pkt.sequence_number, 4); off += 4;
    memcpy(payload + off, &pkt.flags,         1);  off += 1;

    uint8_t computed_mac[32];
    HMAC_SHA256::compute(REX_MASTER_KEY, 32, payload, off, computed_mac);

    if (!HMAC_SHA256::verify(computed_mac, pkt.hmac_sha256)) {
        log_event(ThreatLevel::HIGH, pkt.device_id,
                  "HMAC authentication FAILED — possible tampering/spoofing");
        return false;
    }
    return true;
}

// ── Gateway Packet Processor ──────────────────────────────────
enum class ProcessResult : uint8_t {
    OK           = 0,
    AUTH_FAIL    = 1,
    RATE_LIMITED = 2,
    OUT_OF_RANGE = 3,
    REPLAY       = 4,
};

ProcessResult process_packet(const IoTPacket& pkt) {
    // 1. HMAC Authentication
    if (!auth_check(pkt))
        return ProcessResult::AUTH_FAIL;

    // 2. Rate Limiting
    if (!rate_check(pkt.device_id))  {
        log_event(ThreatLevel::HIGH, pkt.device_id,
                  "Rate limit exceeded — possible DoS attack");
        return ProcessResult::RATE_LIMITED;
    }

    // 3. Replay Attack Check
    if (!replay_check(pkt))
        return ProcessResult::REPLAY;

    // 4. Range Validation
    if (!range_check(pkt))
        return ProcessResult::OUT_OF_RANGE;

    // Packet accepted
    char msg[128];
    snprintf(msg, sizeof(msg), "Packet OK: sensor=0x%02X value=%.2f seq=%u",
             static_cast<uint8_t>(pkt.sensor_type), pkt.value, pkt.sequence_number);
    log_event(ThreatLevel::NONE, pkt.device_id, msg);
    return ProcessResult::OK;
}

#ifndef BUILD_DLL
// ── Print Summary ─────────────────────────────────────────────
static void print_summary() {
    size_t ok = 0, auth_fail = 0, oor = 0;
    for (size_t i = 0; i < g_event_count; ++i) {
        switch (g_event_log[i].threat_level) {
            case ThreatLevel::NONE:   ++ok;        break;
            case ThreatLevel::HIGH:   ++auth_fail; break;
            case ThreatLevel::MEDIUM: ++oor;       break;
            default: break;
        }
    }
    printf("\n══════════════════════════════════════════\n");
    printf("  Rex Gateway Security Processor Summary\n");
    printf("══════════════════════════════════════════\n");
    printf("  Total Events : %zu\n", g_event_count);
    printf("  Accepted     : %zu\n", ok);
    printf("  Auth Failures: %zu\n", auth_fail);
    printf("  Range Errors : %zu\n", oor);
    printf("══════════════════════════════════════════\n\n");
}

// ── Build a test packet with valid HMAC ───────────────────────
static IoTPacket make_test_packet(
    const char* dev_id,
    const char* region,
    SensorType  stype,
    float       value,
    uint32_t    seq
) {
    IoTPacket pkt = {};
    strncpy(pkt.device_id, dev_id, 31);
    strncpy(pkt.region,    region, 31);
    strncpy(pkt.location,  "Farm Zone A", 63);
    pkt.sensor_type     = stype;
    pkt.value           = value;
    pkt.timestamp_ms    = now_ms();
    pkt.sequence_number = seq;
    pkt.flags           = 0x01;  // encrypted flag

    // Compute HMAC over payload
    uint8_t payload[IoTPacket::SERIALIZED_SIZE - 32];
    size_t off = 0;
    memcpy(payload + off, pkt.device_id,       32); off += 32;
    memcpy(payload + off, pkt.region,          32); off += 32;
    memcpy(payload + off, pkt.location,        64); off += 64;
    memcpy(payload + off, &pkt.sensor_type,    1);  off += 1;
    memcpy(payload + off, &pkt.value,          4);  off += 4;
    memcpy(payload + off, &pkt.timestamp_ms,   8);  off += 8;
    memcpy(payload + off, &pkt.sequence_number,4);  off += 4;
    memcpy(payload + off, &pkt.flags,          1);  off += 1;

    HMAC_SHA256::compute(REX_MASTER_KEY, 32, payload, off, pkt.hmac_sha256);
    return pkt;
}
// ── main ──────────────────────────────────────────────────────
int main() {
    printf("════════════════════════════════════════════════════\n");
    printf("  Rex — IoT Gateway Security Processor              \n");
    printf("  Rex C++ Core Engine — Packet Validation Module    \n");
    printf("════════════════════════════════════════════════════\n\n");

    // --- Test 1: Valid packets ---
    printf("[TEST 1] Valid packets from edge node sensors:\n");
    struct { const char* dev; const char* region; SensorType st; float val; } valid_cases[] = {
        {"REX-SOIL-001", "Zone-A",  SensorType::SOIL_MOISTURE,    42.5f},
        {"REX-TEMP-002", "Zone-B",  SensorType::TEMPERATURE,      28.3f},
        {"REX-HUM-003",  "Zone-C",  SensorType::HUMIDITY,         65.0f},
        {"REX-IRR-004",  "Zone-D",  SensorType::IRRIGATION_VALVE,  1.0f},
    };
    for (int i = 0; i < 4; ++i) {
        IoTPacket pkt = make_test_packet(
            valid_cases[i].dev, valid_cases[i].region,
            valid_cases[i].st,  valid_cases[i].val, i + 1
        );
        auto res = process_packet(pkt);
        printf("  %-20s → %s\n", valid_cases[i].dev,
               res == ProcessResult::OK ? "ACCEPTED" : "REJECTED");
    }

    // --- Test 2: Tampered packet ---
    printf("\n[TEST 2] Tampered HMAC packet:\n");
    IoTPacket bad = make_test_packet("ETH-SOIL-001", "Oromia",
                                     SensorType::SOIL_MOISTURE, 42.5f, 99);
    bad.hmac_sha256[0] ^= 0xFF;  // Corrupt the signature
    auto res2 = process_packet(bad);
    printf("  Tampered packet → %s\n",
           res2 == ProcessResult::AUTH_FAIL ? "BLOCKED (auth fail)" : "ERROR");

    // --- Test 3: Out-of-range value ---
    printf("\n[TEST 3] Out-of-range temperature (999°C):\n");
    IoTPacket oor = make_test_packet("ETH-TEMP-002", "Afar",
                                     SensorType::TEMPERATURE, 999.0f, 100);
    auto res3 = process_packet(oor);
    printf("  OOR packet → %s\n",
           res3 == ProcessResult::OUT_OF_RANGE ? "QUARANTINED (range fail)" : "ERROR");

    print_summary();
    return 0;
}
#endif

