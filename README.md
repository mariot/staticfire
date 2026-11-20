# staticfire

A static fire is the test where a rocket engine is fired while held on the pad, before launch.
staticfire does that for OpenAEV injectors and collectors and for OpenCTI connectors: it runs one
from its checkout against a **real platform** and checks every effect it can observe (inject
status and traces, the email that was delivered, the expectation results and traces a collector
pushed; the works of a connector and the STIX it sent).

It sits next to [Mars](../mars) (cloud VMs) and [Liftoff](../liftoff) (deployment): Liftoff
deploys the platform, staticfire fires components at it. It complements Mimikyu and ofapi, which
fake the platform and the vendors: here the platform is real, only the vendor APIs that cannot be
reached are faked.

It is usable three ways, all over the same operations (`src/staticfire/ops.py`):

- a CLI, `staticfire`;
- an MCP server, `staticfire-mcp`, for Claude or any MCP client;
- a Claude Code skill (`~/.claude/skills/staticfire`) that drives the CLI.

## Quick start

```bash
# 1. A platform: OpenAEV + mailpit + an agent on the VM itself (Liftoff, multipass)
cd ../liftoff
SSH_PUBKEY=~/.ssh/id_ed25519.pub just vm-create staticfire 6 16G 60G lts
SSH_KEY_FILE=~/.ssh/id_ed25519 just deploy-openaev staticfire inventory/hosts.staticfire.yml

# 2. A profile pointing at it (reads /opt/xtm/.env in the VM: URL, admin token, mailpit)
cd ../staticfire
uv run staticfire profile from-multipass staticfire

# 3. Fire
uv run staticfire status
uv run staticfire fire                      # list the recipes
uv run staticfire fire email-smtp           # injector test
uv run staticfire fire mailpit-collector    # collector test (mailpit as the email security platform)
uv run staticfire fire cortex-xdr --verdict prevented   # real XDR collector, scripted XDR
```

`uv tool install --editable .` puts `staticfire` and `staticfire-mcp` on the `PATH`.

A Mars/OVH deployment works the same way: `staticfire profile from-ssh ubuntu@<ip> --name ovh`.
Any other platform: `staticfire profile set <name> --url ... --token ... [--mailpit-url ...]`.
Environment variables `STATICFIRE_OPENAEV_URL`, `STATICFIRE_OPENAEV_TOKEN`,
`STATICFIRE_MAILPIT_URL`, `STATICFIRE_SMTP_HOST` override a profile; `STATICFIRE_PROFILE`
selects one.

## Recipes

Each recipe starts what it needs, checks every step and prints a verdict (`PASS`, `FAIL`, `ERROR`)
with links to the inject in OpenAEV and the message in mailpit; `--json` gives the full report
with its evidence (traces, delivered message, expectation results, logs on failure). The exit code
is 0 on `PASS`. Components are stopped at the end unless `--keep`; the vendor fake only if the
recipe started it. ofapi is served on `http://127.0.0.1:8000` and `https://127.0.0.1:8443` by one
process, so both share its scripted rules and journal.

There are 49 OpenAEV recipes in five families; `staticfire fire` lists them with a one-line
description.

| Family | Recipes | How it works | Defined in |
|---|---|---|---|
| Email | `email-smtp`, `mailpit-collector` | `email-smtp` sends through mailpit; the mailpit collector (`collectors/mailpit`, this repo) answers email injects whose implant name sits in a header, a body URL or an attachment (`--carrier header\|url\|attachment\|all\|none`) | `recipes.py` |
| EDR / XDR / SIEM collectors | `cortex-xdr`, `cortex-xsoar`, `crowdstrike`, `sentinelone`, `tanium`, `elastic`, `logrhythm`, `netwitness`, `qradar`, `splunk-es`, `microsoft-defender`, `microsoft-defender-o365`, `microsoft-sentinel`, `microsoft-sentinel-defender` | the agent runs a harmless marker command; ofapi answers the collector with vendor data built from the real expectation signals for `--verdict prevented\|detected\|none`; the collector must report that verdict and have queried its vendor. An email security spec (`email=True`) gets its expectations from an email-smtp inject whose implant is in a body URL, its vendor answering from the delivered message; a SIEM spec chained on an EDR (`edr=`) runs that EDR collector first, on the same expectations | `vendors.py` |
| AI defense | `lakera-guard`, `cisco-ai-defense`, `hiddenlayer`, `prisma-airs`, `prompt-security`, `xtm-one` | `ai-redteam` attacks ofapi's OpenAI-compatible model through an AI target; the firewall's verdict (`--verdict blocked\|flagged\|clean`) is scripted on ofapi; the collector must answer the agentless expectations | `ai_vendors.py` |
| Vendor injectors | `censys`, `shodan`, `slack`, `teams`, `email-google-workspace`, `email-m365`, `nmap`, `netexec`, `prowler`, `stratus`, `aws`, `http-query`, `http-query-form`, `nuclei` | HTTP-API injectors call ofapi; command-line ones run stub tools that reproduce the tool's arguments and output format (so the injector's parser runs for real); checks: status, completion message, findings, vendor calls | `injector_vendors.py` |
| Catalog / asset collectors | `mitre-atlas`, `nvd-nist-cve`, `openaev-payloads`, `aws-resources`, `mitre-attack`, `atomic-red-team`, `microsoft-entra`, `microsoft-intune`, `microsoft-intune-groups`, `microsoft-azure`, `microsoft-azure-subscription`, `google-workspace`, `google-workspace-all-users`, `ovhcloud`, `ovhcloud-oauth2`, `scenarios`, `scenarios-tampered` | the collector imports ofapi's small dataset; the platform must hold what it implies and nothing it excludes (revoked technique, CVE without CVSS v3.1, terminated instance, guest user, suspended server...). The checks read the dataset back from ofapi; a `setup` removes what an earlier run imported. `scenarios` runs dry: its log and GitHub calls are checked | `catalog_vendors.py` |

`staticfire matrix [recipes...] --all-verdicts --out <dir>` runs any set of them one after the
other (they share the platform and the fake), saves each JSON report and prints a summary table;
with no recipe it runs them all (about an hour with every verdict).

Collector recipes first check the platform's clock: collectors judge expectations by their age,
and a multipass VM's clock falls behind while the host sleeps. A skew over two minutes stops the
recipe with the command that fixes it (`multipass exec <vm> -- sudo chronyc makestep`).

Adding a component is adding a spec to one of those files: its settings pointing at the fake, the
vendor answers (or stub) for each verdict, and what must be observed.

`--injector-path` / `--collector-path` test another checkout (a PR branch in a worktree, for
instance); `--pyoaev ../client-python` runs the component on a local pyoaev.

## OpenCTI connectors

Every connector of the connectors repository has a recipe named after its directory
(`staticfire fire hunt-io`, `staticfire matrix --connectors --jobs 4`). The platform is an
OpenCTI deployed by Liftoff (`just deploy-opencti`, then `staticfire profile from-multipass
<vm> --name staticfire-cti`); connector recipes use the first profile holding an OpenCTI.

How a connector test works:

- **The vendor is ofapi, whatever the connector's URL**: the connector's HTTP(S) goes through a
  TLS-intercepting proxy (mitmproxy, `proxy_addon.py`, started on `127.0.0.1:8899` with ofapi)
  which sends each request to the ofapi vendor module declaring its host (`HOSTS` in
  `ofapi/app/vendors/<vendor>.py`). Hardcoded vendor URLs and SDKs need no setting; a host no
  fake claims lands in ofapi's journal under `/_unrouted/<host>/`, and nothing leaves the machine.
  The connector trusts the proxy through `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `AWS_CA_BUNDLE`...
- **Its family decides how it is driven**: an external import runs once; an enrichment is asked
  for an object created for the test; a file import gets a file from ofapi's `/fixtures/`
  (STIX bundle, PDF or text report, MISP event, YARA rules, Navigator layer); an export exports an
  indicator, a report or an intrusion set; a stream connector listens to a live stream while
  objects with unique values are created, and those values must reach its vendor.
- **What it produced is read from its own bundles**: pycti also writes every bundle it sends
  (`CONNECTOR_SEND_TO_DIRECTORY`), so the expected STIX types are checked on what the connector
  sent, whatever OpenCTI already held. Its works must complete without error.
- **Each connector runs under its own OpenCTI service account** (`staticfire-<recipe>`, group
  Connectors, token kept in `~/.local/state/staticfire/opencti-users.json`), so its writes are
  attributable; the report lists what it created or updated.
- Settings: the recipe's own (OpenCTI, name, `CONNECTOR_DURATION_PERIOD`, `CONNECTOR_AUTO=false`,
  the live stream), the connector's docker-compose environment (connectors without a config
  schema read config.yml, which a test has not), a placeholder for every required setting of its
  config schema, then the spec's.
- The log review covers the connector's log, OpenCTI's and the workers' (where ingestion errors
  show); any ERROR in the connector's own log fails the test (connectors often catch their
  failures and still complete their work).
- **AWS is emulated** by moto inside ofapi (`aws.py`, every `*.amazonaws.com` host: S3, STS,
  EC2...); `fake.s3_put(bucket, key, content, region)` seeds S3.
- **The network stops at the machine**: a `sitecustomize` (`shims.py`) makes hosts outside the test
  unresolvable and refuses connections to public addresses, so a client ignoring the proxy fails
  instead of reaching the real vendor (`STATICFIRE_NETWORK_ALLOW` lets a spec allow one host). It
  also points certifi at the proxy's CA bundle, resolves `rabbitmq` to the platform, and stands in
  for python-magic when libmagic is missing.
- Specs can seed OpenCTI before the run (`prepare`), check it after (`verify`), follow a filtered
  live stream of their own (`stream_filters`), be judged on what their account created when the
  connector opens no work (`opens_work=False`), and leave out a setting the recipe sets (`None`).
- Connectors are independent: `--jobs` runs several at once (the journal checks only count calls
  made since the test started; each run starts from a reset state). A connector that cannot run
  offline has a spec saying why and reports `SKIP`.

Coverage: every connector of the repository has a spec (384 specs for 326 connectors, several
scenarios for some); 3 are SKIP (LibreOffice, AMQP input, OpenDXL). The defects these tests
exposed are listed under "Known gaps".

Specs live in `src/staticfire/connectors/` (one module per connector), vendor fakes in ofapi's
`app/vendors/` (one module per vendor, loaded live by `POST /_control/reload`).

## Building blocks

For components without a recipe, the same steps are available one by one:

```bash
staticfire up ../injectors/nmap -e SOME_SETTING=value   # install, start, wait for registration
staticfire contracts ../injectors/nmap                  # its contracts and their fields
staticfire inject <contract-id> --set key=value --asset <endpoint-id> --expect DETECTION
staticfire inject <contract-id> --content '{"headers": [{"key": "X-A", "value": "1"}]}'
staticfire report <inject-id> --asset <endpoint-id>     # status, traces, expectation results
staticfire logs injector-nmap --grep error
staticfire down injector-nmap

staticfire fake up                            # ofapi over TLS on https://127.0.0.1:8443, prints the CA
staticfire up ../injectors/http-query -e REQUESTS_CA_BUNDLE=<ca>
staticfire inject <get-contract-id> --set uri=https://127.0.0.1:8443/echo
staticfire fake journal --path /echo          # exactly what the injector sent
staticfire fake down

staticfire agent-expectations                 # the agent runs `echo staticfire-marker <id>`
staticfire expectations --inject <inject-id>  # what a collector receives, with signatures
staticfire up ../collectors/crowdstrike -e CROWDSTRIKE_API_BASE_URL=...
staticfire wait-expectations <inject-id> <endpoint-id> --source <collector-id>

staticfire scenario <scenario-id>             # launch a simulation, wait for its injects
staticfire mail search 'to:"x@y.z"'
```

- Commands print JSON; `fire` prints a summary (`--json` for the full report).
- `inject` fills the fields you leave out with the contract defaults, like the UI form does
  (`--no-defaults` to send only yours): injectors read optional fields without checking for them.
  `--set` gives one string field, `--content` any JSON (list fields take `{"key", "value"}` items).
- Components and the fake run on this machine, the platform and the agent in the VM: `127.0.0.1`
  in an inject is this machine.
- Components run detached; their virtualenvs live in `~/.local/state/staticfire/venvs/` (the
  lowest Python the component allows, never below 3.12 since pyoaev needs it; `up --python 3.13`
  to force one), their logs and pids in `~/.local/state/staticfire/runs/`. Each gets a stable id
  derived from its name, so reruns reuse the platform-side registration.

## MCP server

```bash
claude mcp add staticfire -- uv --directory ~/GitHub/staticfire run staticfire-mcp
```

A recipe takes one to three minutes; if the client gives up first, raise its tool timeout (Claude
Code: `MCP_TOOL_TIMEOUT`, in milliseconds).

Tools: `status`, `list_recipes`, `fire_recipe`, `component_up`, `component_down`,
`component_logs`, `list_runs`, `injector_contracts`, `run_inject`, `inject_report`,
`pending_expectations`, `agent_expectations`, `wait_expectations`, `launch_scenario`,
`vendor_fake`, `mail_search`.

## How the platform side works (what staticfire relies on)

- **Atomic testings** are created with `POST /api/atomic-testings` and launched with
  `POST /api/atomic-testings/{id}/launch`; scenarios with `POST /api/scenarios/{id}/exercise/running`
  (chained workflows included), which starts the simulation at the next minute.
- **Collectors only see agent expectations**: `GET /api/injects/expectations/assets/{source}`
  returns DETECTION/PREVENTION expectations that have an agent. They exist when an inject targets
  an endpoint with an active agent and carries expectations; any contract works (the email inject
  of `mailpit-collector` does), the marker payload gives the realistic signatures EDR collectors
  match on (`oaev-implant-<inject>-agent-<agent>`, start and end dates, addresses).
- **Results**: `GET /api/atomic-testings/{id}/target_results/{asset}/types/ASSETS`. OpenAEV creates an
  empty result slot (`result: null`) per collector it expects an answer from, so only results with a
  value count as answers.
- **The API client never sends cookies**: a bearer request carrying the session cookie of a previous
  response is treated as a browser session, and its bodyless POSTs (launch) fail the CSRF check.

## Known gaps found with staticfire

Filed: [injectors#534](https://github.com/OpenAEV-Platform/injectors/issues/534) (email implant
name), [client-python#385](https://github.com/OpenAEV-Platform/client-python/issues/385) (signature
trace message).

- Email injects can be matched like agent ones: their expectations carry the implant name
  (`parent_process_name` = `<injector type><inject>-agent-<agent>`), and an email carrying it in an
  `X-OpenAEV-*` header, a body URL or an attachment is matched by the mailpit collector. But
  `email-smtp` never writes it (an inject author cannot either: no content variable gives the
  inject or agent id), so the recipe edits the inject; and `microsoft-defender-o365` reads neither
  headers (`custom_header` is hardcoded to `""`) nor the implant in URLs or attachments.
- The email signatures `email-smtp` builds (`source_email`, `target_email`, URL and attachment
  hashes, custom headers) never reach the expectations: they are sent in
  `execution_output_structured` as a flat dictionary, while the platform's
  `SignatureOutputProcessor` reads a `targets[]` list and silently skips anything else; and its
  signature-manager payload has no agent/asset target, which the platform drops too.
- Every signature callback leaves a trace reading `Current action: data - Current status: data`:
  pyoaev's `ExecutionDetails.execution_message` (`pyoaev/signatures/models.py`) fills the status
  half from `execution_action` instead of `execution_status`.
- pyoaev 3.261118.0 declares `requires-python >=3.11` but imports `typing.override` (3.12+), so
  a component installed on 3.11 fails at its first import.
- `crowdstrike` and `openaev` collectors fail at startup without `COLLECTOR_NAME`: their
  settings do not override pyoaev's required `name`, while their READMEs document a default
  (every other collector has one).
- `http-query` fails with `'basicAuth'` (a `KeyError`) when an inject omits that optional field;
  the UI always sends it, an API client may not.
- The AI request marker signatures (`ai_request_marker`, `ai_target_endpoint`) are defined in the
  platform but never attached: `AiSignatureUtils.computeAiSignatures` has no caller, so AI
  expectations only carry `parent_process_name`. The AI collectors work around it by recomputing
  the marker.
- Not filed yet, found by the proxy recipes (each recipe named reproduces it):
  - pyoaev's `http_put` parses every answer as JSON, while `PUT /api/injects/expectations/bulk`
    answers 200 with an empty body: every successful bulk update raises, and the Microsoft
    collectors redo each update one by one (`microsoft-defender`, warning in its log).
  - `microsoft-defender-o365` can match no expectation: the platform's expectations carry
    `parent_process_name` only, which the alert data never holds, and its engine requires every
    signature type (`microsoft-defender-o365 --verdict prevented`). It also answers "Not
    Detected" at its first poll: it has no retry window.
  - `microsoft-sentinel` matches on the `alertId` an EDR collector recorded; `microsoft-defender`
    (the pairing its README gives) records none (`microsoft-sentinel-defender`).
  - `microsoft-entra` imports no user (`include_external` reaches it as 0/1, compared with
    `is True`/`is False`) and stops at the second page of groups (`groups.with_url(...)` is
    awaited without `.get()`) (`microsoft-entra`).
  - `microsoft-intune` and `microsoft-azure` crash without a device group / resource group
    (`device_groups_list` / `resource_groups_list` never set) (`microsoft-intune`,
    `microsoft-azure-subscription`); Intune device groups are looked up with
    `resourceProvisioningOptions/Any(x:x eq 'Intune')`, which no security group has
    (`microsoft-intune-groups`).
  - `atomic-red-team` turns `Test-Path PathToAtomicsFolder\...\file.ps1)` into an argument named
    `file_ps1)_atomicredteam_path` and an unbalanced check command (`atomic-red-team`).
  - `ovhcloud` reads `image` and `flavor` from `GET /cloud/project/{id}/instance`, whose items
    (`cloud.instance.Instance`) only have `imageId` and `flavorId`: Public Cloud instances get
    platform Unknown (`ovhcloud`).
  - `google-workspace` (httplib2) ignores an HTTPS proxy unless PySocks is installed, and reports
    "Synchronization completed successfully" when its token request fails.

Components with a hardcoded vendor host (Microsoft, Google, OVHcloud, GitHub) run with
`proxy=True`: their HTTP(S) goes through the TLS-intercepting proxy to the ofapi module declaring
that host, as for OpenCTI connectors. Recipes reset ofapi's rules and journal under their own
paths only (a prefix several vendors share, such as `/microsoft-graph` or `/github`, is never reset
whole), and requests a test makes itself to ofapi carry `X-Staticfire-Check`, which
`Ofapi.journal()` leaves out.

## Development

```bash
uv sync
uv run pytest
uv run ruff check src collectors tests && uv run ruff format --check src collectors tests
```
