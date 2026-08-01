# Falco Alert Triage Workflow

Detection without a triage habit is a Slack channel people mute. This is the
workflow that kept our channel unmuted: every alert gets a disposition, and
every false positive becomes a tuning commit.

## Severity contract

The rules and the Slack routing (`minimumpriority: warning`) implement this
contract:

| Priority | Meaning | Response |
|---|---|---|
| CRITICAL | Active-compromise indicators (mining pool contact, kernel module from container) | Page. Respond now. |
| WARNING | Suspicious, needs a human within the workday (exec shells, SA-token reads, package managers) | Triage same day |
| NOTICE / INFO | Context, hunting material | Logs + metrics only, reviewed in aggregate |

If a rule keeps producing CRITICALs nobody pages on, either the response is
wrong or the priority is — fix one of them, never learn to ignore it.

## Per-alert triage (target: under 5 minutes)

Every custom rule's output line carries the needed context: namespace, pod,
image, process, command line, user.

1. **Identify the workload.**
   ```bash
   kubectl -n <ns> get pod <pod> -o wide
   kubectl -n <ns> describe pod <pod> | grep -A5 'Controlled By\|Image'
   ```
2. **Attribute the actor.** For exec-shell alerts, the Kubernetes audit log
   answers *who*; Falco answered *what and where*:
   ```bash
   # audit log query shape (adapt to your log backend)
   verb=create AND objectRef.subresource=exec AND objectRef.name=<pod>
   ```
3. **Disposition — one of exactly four:**
   - **True positive** → incident process (isolate first, see below).
   - **Authorized activity, expected to recur** → tuning commit: exception
     scoped to namespace + image/identity in
     `rules/tuning-noisy-defaults.yaml`, with reason in a comment. PR-review
     it like code — exceptions are attack surface.
   - **Authorized one-off** (declared debugging) → acknowledge, no tuning.
     If the same "one-off" appears three times, it is recurring; tune it.
   - **Rule defect** (wrong condition, missing field) → fix the rule itself.
4. **Record the disposition** — thread reply on the alert is fine. The
   record is what turns week-over-week noise review from guessing into data.

## True-positive first moves (containment order)

1. **Isolate, don't kill.** Label-based network quarantine preserves the
   forensic state a `kubectl delete pod` destroys:
   ```bash
   kubectl -n <ns> label pod <pod> quarantine=true --overwrite
   # with a pre-provisioned deny-all NetworkPolicy selecting quarantine=true
   ```
2. **Capture state**: `kubectl logs` (+ `--previous`), pod spec, node name,
   container image digest, and the surrounding Falco events for that pod.
3. **Rotate what the pod could reach**: its ServiceAccount tokens first
   (delete the SA's secrets / restart consumers), then any Secrets mounted
   into the pod.
4. **Then** delete the workload and dig into how it got there (image
   provenance, admission logs).

## Weekly noise review (30 minutes, calendar-blocked)

- Top rules by alert count (falcosidekick Prometheus metrics:
  `falcosecurity_falcosidekick_falco_events_total` by rule).
- Any rule > ~20 alerts/week with zero true positives is a tuning candidate —
  scope it down or downgrade it deliberately; never let it train people to
  scroll past.
- Review the exceptions file for entries whose reason no longer holds
  (deprecated namespaces, removed agents). Exceptions rot faster than rules.

## Tuning principles

- Prefer **exceptions** (scoped carve-outs) over editing rule conditions;
  prefer condition edits over disabling; disable almost never.
- Scope exceptions to at least two fields (namespace + image prefix) so an
  attacker cannot inherit an exception by naming a binary `node-exporter`.
- Never exempt an entire cluster or all containers from a rule — at that
  point delete the rule honestly instead.
