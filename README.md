# TunnelScope

Evidence-based MTU and packet-size diagnostics for Linux networks.

**Status: project initialization. No diagnostic implementation or installable release is available yet.**

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

There is no installation command yet. The first deliverable is the M0 lab, not a dashboard. Implementation and reproducible instructions will be added as each milestone is completed.

## Prior art and scope

Existing tools such as ping, tracepath and packet analyzers already provide important building blocks. TunnelScope will explore whether controlled two-endpoint tests and evidence-oriented reporting make this investigation easier. It is not a replacement for a full packet analyzer.

## Contributing

Early feedback is welcome through GitHub Issues, especially reproducible examples where small traffic succeeds and larger transfers fail. Describe the environment, expected behavior and observed behavior. Use synthetic or sanitized examples; do not attach credentials or private packet captures.

## Türkçe özet

TunnelScope, küçük veriler giderken büyük verilerin neden takıldığını araştırmayı kolaylaştırmayı amaçlayan açık kaynak bir ağ teşhis projesidir.

İlk hedefimiz, iki Linux ortamı arasında farklı boyutlarda kontrollü testler yapıp sonuçları raporlamak. Her başarısız testi MTU sorunu saymayacağız; gözlemlediklerimizi tahminlerimizden ayıracağız.

Proje henüz başlangıç aşamasında. İlk görev: sorunu küçük bir laboratuvarda oluşturmak, ölçmek ve açıklamak.
