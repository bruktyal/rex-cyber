import sys
import argparse
import time
import os
import json
import logging
from rex.config import RexConfig
from rex.engine import RexEngine
from rex.dashboard.soc import SOCDashboard
from rex.nids.rule import NetworkPacket

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("Rex.CLI")


def run_demo():
    print("\n" + "=" * 60)
    print("  REX IoT SECURITY FRAMEWORK — CORE ENGINE DEMO")
    print("=" * 60)
    
    # 1. Initialize Engine and Dashboard
    config = RexConfig()
    engine = RexEngine(config)
    dash = SOCDashboard(log_dir=config.log_dir)

    # 2. Register devices
    devices = [
        ("REX-NODE-001", "Zone-A", "soil_moisture"),
        ("REX-NODE-002", "Zone-B", "temperature"),
        ("REX-NODE-003", "Zone-C", "humidity"),
    ]
    for dev_id, region, stype in devices:
        dash.register_device(dev_id, region, stype)

    # 3. Process normal packets
    print("\n[STEP 1] Ingesting validated sensor readings...")
    # Generate signature using HMAC
    import hashlib
    import hmac
    from rex.engine import REX_MASTER_KEY_BYTES
    secret_bytes = REX_MASTER_KEY_BYTES
    
    for dev_id, region, stype in devices:
        t_ms = int(time.time() * 1000)
        value = 25.0
        payload = engine.serialize_packet(
            device_id=dev_id,
            region=region,
            location="East-Field",
            sensor_type=stype,
            value=value,
            timestamp_ms=t_ms,
            sequence_number=1,
            flags=0
        )
        sig = hmac.new(secret_bytes, payload, hashlib.sha256).digest()
        
        res = engine.validate_packet(
            device_id=dev_id,
            region=region,
            location="East-Field",
            sensor_type=stype,
            value=value,
            sequence_number=1,
            timestamp_ms=t_ms,
            hmac_signature=sig
        )
        dash.update_device(dev_id, value)
        print(f"  {dev_id} ({stype}={value}) -> Status: {res['status']} | Source: {res.get('source', 'N/A')}")

    # 4. Trigger rate limit alerts
    print("\n[STEP 2] Simulating high-frequency DoS / Flooding attack...")
    seq_num = 2
    for _ in range(config.max_packet_rate + 10):
        t_ms = int(time.time() * 1000)
        payload = engine.serialize_packet(
            device_id="REX-NODE-001",
            region="Zone-A",
            location="East-Field",
            sensor_type="soil_moisture",
            value=35.0,
            timestamp_ms=t_ms,
            sequence_number=seq_num,
            flags=0
        )
        sig = hmac.new(secret_bytes, payload, hashlib.sha256).digest()
        
        res = engine.validate_packet(
            device_id="REX-NODE-001",
            region="Zone-A",
            location="East-Field",
            sensor_type="soil_moisture",
            value=35.0,
            sequence_number=seq_num,
            timestamp_ms=t_ms,
            hmac_signature=sig
        )
        seq_num += 1
        if res["status"] != "OK":
            dash.log_event({
                "device_id": "REX-NODE-001",
                "threat_level": "HIGH",
                "description": res.get("reason", "unknown error")
            })
            print(f"  --> Blocked Flooding Event: {res['reason']}")
            break

    # 5. Statistical anomalies
    print("\n[STEP 3] Inducing rolling statistical anomalies...")
    # Build baseline history for REX-NODE-002
    for seq in range(2, 15):
        t_ms = int(time.time() * 1000)
        val = 20.0  # Normal stable readings
        payload = engine.serialize_packet(
            device_id="REX-NODE-002",
            region="Zone-B",
            location="East-Field",
            sensor_type="temperature",
            value=val,
            timestamp_ms=t_ms,
            sequence_number=seq,
            flags=0
        )
        sig = hmac.new(secret_bytes, payload, hashlib.sha256).digest()
        engine.validate_packet(
            device_id="REX-NODE-002", region="Zone-B", location="East-Field",
            sensor_type="temperature", value=val, sequence_number=seq,
            timestamp_ms=t_ms, hmac_signature=sig
        )
        time.sleep(0.11)
        
    # Anomaly spike
    time.sleep(0.15)
    t_ms = int(time.time() * 1000)
    payload = engine.serialize_packet(
        device_id="REX-NODE-002",
        region="Zone-B",
        location="East-Field",
        sensor_type="temperature",
        value=85.0,
        timestamp_ms=t_ms,
        sequence_number=16,
        flags=0
    )
    sig = hmac.new(secret_bytes, payload, hashlib.sha256).digest()
    res = engine.validate_packet(
        device_id="REX-NODE-002", region="Zone-B", location="East-Field",
        sensor_type="temperature", value=85.0, sequence_number=16,
        timestamp_ms=t_ms, hmac_signature=sig
    )
    if res["status"] == "ANOMALY":
        dash.log_event({
            "device_id": "REX-NODE-002",
            "threat_level": "MEDIUM",
            "description": f"Value spike anomaly: temperature=85.0"
        })
        print(f"  --> Flagged Anomaly Event: {res['reason']}")

    # 6. Render dashboard
    print("\n[STEP 4] Printing live SOC dashboard...")
    dash.print_dashboard()
    
    # Export compliance report
    report_file = os.path.join(config.log_dir, "rex_report.json")
    dash.export_json(report_file)
    print(f"  Demo complete. Exported report to: {report_file}\n")


def run_report():
    config = RexConfig()
    report_file = os.path.join(config.log_dir, "rex_report.json")
    if not os.path.exists(report_file):
        print(f"\nERROR: No compliance reports found in {config.log_dir}.")
        print("Run 'rex-cli demo' to generate a live report.\n")
        return

    try:
        with open(report_file, "r") as f:
            data = json.load(f)
        print("\n" + "=" * 60)
        print(f"  REX COMPLIANCE ARCHIVE REPORT — {data.get('report_id')}")
        print("=" * 60)
        print(f"  Generated   : {data.get('generated_at')}")
        print(f"  Compliance  : {data.get('compliance_score')}% Score")
        print(f"  Total Nodes : {data.get('total_devices')} Devices")
        print(f"  Threat Count: {data.get('total_alerts')} Events")
        print("-" * 60)
        print("  Key Mitigation Guidelines:")
        for i, rec in enumerate(data.get("recommendations", []), 1):
            print(f"    {i}. {rec}")
        print("=" * 60 + "\n")
    except Exception as e:
        print(f"Failed to read report file: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Rex — Performance-Accelerated IoT Security Framework CLI"
    )
    parser.add_argument(
        "command",
        choices=["demo", "report"],
        help="Command to run: 'demo' (simulate pipeline threats), 'report' (view latest compliance score)",
    )
    
    args = parser.parse_args()
    
    if args.command == "demo":
        run_demo()
    elif args.command == "report":
        run_report()


if __name__ == "__main__":
    main()
