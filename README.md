# Falco Rules Pack

A reference set of [Falco](https://falco.org) runtime-detection rules,
tuning overrides, and deployment values — distilled from operating Falco on
production Kubernetes clusters. Detection only: rules observe and alert;
response stays with humans and documented runbooks.

The pack ships seven custom rules, each mapped to a real attacker behaviour:

| Rule | Priority | Behaviour caught |
|---|---|---|
| Interactive Shell in Container | NOTICE | Post-exploit interactive access |
| Shell Spawned via Kubectl Exec | WARNING | Exec sessions (correlate with audit logs for identity) |
| Sensitive Host Path Opened in Container | WARNING | Escape recon, over-broad hostPath mounts |
| Outbound Connection to Mining Pool | CRITICAL | Cryptomining payloads (stratum ports + pool domains) |
| Package Manager in Container | WARNING | Runtime tool-staging in immutable images |
| Kernel Module Load from Container | CRITICAL | Rootkit staging, container escape |
| Unexpected Read of ServiceAccount Token | WARNING | In-cluster credential harvesting |

## Structure

```
.
├── rules/
│   ├── custom-rules.yaml            # 7 detection rules + shared lists/macros
│   └── tuning-noisy-defaults.yaml   # Exceptions & overrides for known false positives
├── deploy/
│   └── falco-values.yaml            # Helm values: modern eBPF, falcosidekick -> Slack
└── docs/
    └── triage-workflow.md           # Severity contract, 5-minute triage, containment
```

## Usage

```bash
# Validate rule syntax before deploying (uses the falco container locally)
docker run --rm -v "$PWD/rules:/rules:ro" falcosecurity/falco:0.39.2 \
  falco -V /rules/custom-rules.yaml -V /rules/tuning-noisy-defaults.yaml

# Deploy via helm, injecting rules and the Slack webhook at install time
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm upgrade --install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  -f deploy/falco-values.yaml \
  --set-file 'customRules.10-custom-rules\.yaml'=rules/custom-rules.yaml \
  --set-file 'customRules.90-tuning-noisy-defaults\.yaml'=rules/tuning-noisy-defaults.yaml \
  --set falcosidekick.config.slack.webhookurl="$SLACK_WEBHOOK_URL"
```

The Slack webhook is a secret: it is injected at deploy time and this repo's
`.gitignore` refuses webhook-shaped files on principle.

## Design notes

- **Few rules, all triaged.** Every alert priority carries a response
  contract (see [docs/triage-workflow.md](docs/triage-workflow.md)); only
  WARNING+ reaches Slack. A channel full of NOTICEs gets muted, and a muted
  channel is a disabled detection system with better dashboards.
- **Tuning is code.** False positives become scoped `exceptions` in
  `rules/tuning-noisy-defaults.yaml`, each with a named reason, each
  reviewed like any other change. Exceptions pin at least two fields
  (namespace + image prefix) so they cannot be inherited by renaming a
  binary.
- **Output lines are runbooks' inputs.** Every rule emits namespace, pod,
  image, process, and command line — the responder should never need a
  second query to know what fired and where.
- **modern_ebpf driver** — no kernel header compilation on node images,
  which removes the classic Falco upgrade failure mode.

## License

MIT — see [LICENSE](LICENSE).
