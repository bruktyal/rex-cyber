# Rex — Generalized C++ Accelerated IoT Security Framework

Rex is a production-ready, high-performance security framework designed to protect IoT sensor networks against common edge threats, authentication spoofing, replay attacks, sliding-window denial of service, and statistical telemetry anomalies.

## Key Abstractions

- **C++ Accelerated Core Engine**: Leverages standard, timing-safe C++ operations for sub-microsecond processing of cryptographic packet validation.
- **Dynamic Key Management**: Pluggable key exchange using Curve25519 and automatic key rotation mechanisms.
- **Statistical Anomaly Detection**: Tracks telemetry values over rolling standard deviation profiles to flag spikes.
- **Behavioral Network NIDS**: Modular intrusion detection matching packet flows against protocol-level filters.
- **SOC Compliance Scoring**: Built-in reporting system computing real-time network safety grades.

## Getting Started

Run the interactive CLI simulation:
```bash
rex-cli demo
```

To display the generated security compliance grade:
```bash
rex-cli report
```
