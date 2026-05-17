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
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    
    console = Console()
    console.print(Panel.fit("[bold green]  REX IoT SECURITY FRAMEWORK — CORE ENGINE DEMO  [/bold green]", subtitle="High-Performance Edge Protection", border_style="green"))
    
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
    console.print("\n[bold cyan][STEP 1] Ingesting validated sensor readings...[/bold cyan]")
    # Generate signature using HMAC
    import hashlib
    import hmac
    from rex.engine import REX_MASTER_KEY_BYTES
    secret_bytes = REX_MASTER_KEY_BYTES
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, complete_style="green", finished_style="bold green"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[green]Verifying HMAC signatures...", total=len(devices))
        for dev_id, region, stype in devices:
            time.sleep(0.4)  # Live delay simulation
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
            console.print(f"  [bold green]✓[/bold green] {dev_id} ({stype}={value}) -> Status: [green]{res['status']}[/green] | Source: [cyan]{res.get('source', 'N/A')}[/cyan]")
            progress.advance(task)

    # 4. Trigger rate limit alerts
    console.print("\n[bold red][STEP 2] Simulating high-frequency DoS / Flooding attack...[/bold red]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, complete_style="red", finished_style="bold red"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        total_packets = config.max_packet_rate + 10
        task = progress.add_task("[red]Ingesting fast packet burst...", total=total_packets)
        seq_num = 2
        for _ in range(total_packets):
            time.sleep(0.05)  # Rapid packets
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
            progress.advance(task)
            if res["status"] != "OK":
                dash.log_event({
                    "device_id": "REX-NODE-001",
                    "threat_level": "HIGH",
                    "description": res.get("reason", "unknown error")
                })
                console.print(f"  [bold red]✕[/bold red] --> [bold red]Blocked Flooding Event:[/bold red] {res['reason']}")
                break

    # 5. Statistical anomalies
    console.print("\n[bold yellow][STEP 3] Inducing rolling statistical anomalies...[/bold yellow]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, complete_style="yellow", finished_style="bold yellow"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[yellow]Warming up baseline...", total=14)
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
            time.sleep(0.08)
            progress.advance(task)
            
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
            console.print(f"  [bold yellow]✕[/bold yellow] --> [bold yellow]Flagged Anomaly Event:[/bold yellow] {res['reason']}")

    # 6. Render dashboard
    console.print("\n[bold cyan][STEP 4] Printing live SOC dashboard...[/bold cyan]")
    dash.print_dashboard()
    
    # Export compliance report
    report_file = os.path.join(config.log_dir, "rex_report.json")
    dash.export_json(report_file)
    console.print(f"\n[bold green]Demo complete![/bold green] Exported report to: [cyan]{report_file}[/cyan]\n")


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
