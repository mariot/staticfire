# staticfire

A static fire is the test where a rocket engine is fired while held on the pad, before launch.
staticfire does that for OpenAEV injectors and collectors: it runs one from its checkout against a
**real OpenAEV platform** and checks every effect it can observe (inject status and traces, the
email that was delivered, the expectation results and traces a collector pushed).

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
recipe started it.

| Recipe | What is fired | What is checked |
|---|---|---|
| `email-smtp` | `injectors/email-smtp` sends a crafted email through mailpit | inject `EXECUTED`, injector `COMPLETE` trace, message delivered with the sender, To/Cc, subject, body and `X-OpenAEV-*` header of the inject |
| `mailpit-collector` | email injects targeting an agent endpoint with DETECTION/PREVENTION expectations, their implant name written in an `X-OpenAEV-Implant` header, a body URL or an attachment (`--carrier header\|url\|attachment\|all`, `none` for the negative case); `collectors/mailpit` (this repo) plays the email security platform | per carrier: the email carries the implant, the collector answers `Detected` / `Not Prevented` and records the carrier it matched; with `none` it answers nothing |
| `cortex-xdr` | the agent runs a marker command; ofapi plays Cortex XDR and reports alerts on that implant; `collectors/palo-alto-cortex-xdr` runs against both | `--verdict prevented`: `Detected` + `Prevented`; `detected`: `Detected`, prevention left pending; `none`: nothing answered. The collector must have queried the XDR alerts API |

`--injector-path` / `--collector-path` test another checkout (a PR branch in a worktree, for
instance); `--pyoaev ../client-python` runs the component on a local pyoaev.

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
- pyoaev 3.261118.0 declares `requires-python >=3.11` but imports `typing.override` (3.12+), so
  a component installed on 3.11 fails at its first import.
- `http-query` fails with `'basicAuth'` (a `KeyError`) when an inject omits that optional field;
  the UI always sends it, an API client may not.
- Every signature callback leaves a trace reading `Current action: data - Current status: data`:
  pyoaev's `ExecutionDetails.execution_message` (`pyoaev/signatures/models.py`) fills the status
  half from `execution_action` instead of `execution_status`.

## Development

```bash
uv sync
uv run pytest
uv run ruff check src collectors tests && uv run ruff format --check src collectors tests
```
