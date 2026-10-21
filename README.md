<p align="center">
  <img src="tunnelscope-logo.png" alt="TunnelScope monochrome vortex emblem" width="200">
</p>

# TunnelScope

Evidence-based MTU and packet-size diagnostics for Linux networks.

**Status: early prototype. A bounded UDP sender/receiver is available from source. MTU diagnosis, disabled fragmentation and a Linux failure lab are not implemented yet. No packaged release is available.**

## The problem

A connection can appear healthy while larger transfers fail. Small probes may succeed even when larger packets cannot traverse the path. Tunnel overhead, MTU configuration and blocked Path MTU Discovery feedback can contribute to this behavior. Other causes can produce similar symptoms.

TunnelScope aims to help network engineers, system administrators and learners investigate these failures through repeatable measurements and inspectable evidence.

## Planned first version

- A Python command-line tool and a cooperating receiver for controlled Linux environments.
- Repeated, size-controlled IPv4 UDP probes with fragmentation disabled.
- Separate measurements for each direction, with timeouts and loss recorded explicitly.
- JSON reports containing probe sizes, outcomes, relevant interface information and test settings.
- A reproducible Linux lab demonstrating healthy delivery, explicit packet-too-large feedback and a possible PMTU black hole.

A failed probe alone will not be labeled as proof of an MTU problem. Reports will separate observations, hypotheses and missing evidence. An observed working packet size will not automatically be presented as the exact path MTU.

## Milestones

- [ ] **M0 - Reproduce the problem:** build a small Linux network-namespace lab and record a healthy baseline and a controlled MTU failure.
- [ ] **M1 - Probe and receive:** implement bounded, identifiable probes and acknowledgements between two endpoints.
- [ ] **M2 - Explain the evidence:** export JSON and distinguish successful delivery, explicit errors and inconclusive timeouts.
- [ ] **M3 - Validate:** check the tool against known lab configurations, document limitations and publish a short demo.

Kubernetes, VPN-specific workflows, IPv6 and 5G user-plane tunnels are possible later directions. They are not currently supported features.

## Getting started

Requires Python 3.10 or newer. No third-party packages are needed. Start with a local experiment in two terminals, from the repository directory.

Terminal 1 (receiver):

```sh
python tunnelscope.py receive
```

Terminal 2 (sender):

```sh
python tunnelscope.py probe 127.0.0.1 --sizes 64,512,1200,1400 --count 3 --output report.json
```

The receiver exits after 100 datagrams or 30 seconds without a datagram. Restart it if it has already exited. `--max-packets` and `--idle-timeout` change these limits.

Probe sizes are **UDP payload bytes**, including TunnelScope's 24-byte header. They exclude IP and UDP headers. The receiver sends only a small acknowledgement, so this is not a same-sized round-trip test. Reverse endpoint roles to investigate delivery in the other direction.

`acknowledged` means that the receiver got that payload and its acknowledgement returned. `timeout` means no matching acknowledgement arrived before the deadline; it does not prove an MTU issue. `socket_error` records a local socket error. Fragmentation currently follows OS defaults, so even a large successful datagram does not establish the path MTU. The CLI exits successfully when it produces a report; inspect per-probe statuses for delivery outcomes.

The receiver binds to loopback by default. For your own two-host lab, use `--bind <receiver-lab-IPv4>` and probe that address. The experimental protocol is unencrypted and unauthenticated; use a controlled lab, not a public service.

Run checks:

```sh
python -m unittest discover -s tests -v
```

Türkçe ilk deney: [İlk adım rehberi](docs/ilk-deney.md).

## Prior art and scope

Existing tools such as ping, tracepath and packet analyzers already provide important building blocks. TunnelScope will explore whether controlled two-endpoint tests and evidence-oriented reporting make this investigation easier. It is not a replacement for a full packet analyzer.

## Contributing

Early feedback is welcome through GitHub Issues, especially reproducible examples where small traffic succeeds and larger transfers fail. Describe the environment, expected behavior and observed behavior. Use synthetic or sanitized examples; do not attach credentials or private packet captures.

## Türkçe özet

TunnelScope, küçük veriler giderken büyük verilerin neden takıldığını araştırmayı kolaylaştırmayı amaçlayan açık kaynak bir ağ teşhis projesidir.

İlk hedefimiz, iki Linux ortamı arasında farklı boyutlarda kontrollü testler yapıp sonuçları raporlamak. Her başarısız testi MTU sorunu saymayacağız; gözlemlediklerimizi tahminlerimizden ayıracağız.

İlk çalışan parça: farklı boyutlarda UDP verisi gönderen ve küçük bir onay mesajıyla teslimi kontrol eden Python aracı. Henüz MTU teşhisi yapmıyor. Sonraki görev: paket parçalanmasını kontrol etmek ve sorunu küçük bir Linux laboratuvarında oluşturmak.
