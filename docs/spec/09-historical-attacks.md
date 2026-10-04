# 9. Historical attack and supply-chain mitigation

Past attacks on AI infrastructure rarely came through prompt text. They came through
model files, model repositories, agent code-execution tools and exposed model servers.
v2 covers each with a control and feeds the patterns from an external, versioned file.

| Attack class | How it happened | Control in v2 |
| --- | --- | --- |
| Unsafe deserialization | Pickle-based model files (PyTorch `.bin`, `.pt`) run code when loaded | Model file scanner: stdlib `pickletools` lists every imported global; anything outside an allowlist (`torch`, `numpy`, `collections`, `_codecs`) fails. Prefer GGUF or safetensors. |
| Malicious or swapped models | Typosquatted or poisoned repositories on public hubs; a model silently replaced | `models.allowed` with digest pinning, checked at startup, on reload and by `/health` against Ollama `/api/tags`. Repository blocklist in the feed. |
| Code execution through agents | Model output or tool arguments carrying shell commands, `eval`, `__import__`, `pickle.loads` into a code tool | Signatures applied to model output and client tool arguments, not only prompts. High-severity patterns (pipe-to-shell, reverse shell) block; others log. |
| Remote-code loading | `trust_remote_code=True`, model URLs from untrusted hosts | URL and option patterns in the feed, applied to every text surface. |
| Exposed model server | Model APIs reachable from the network without authentication | Deployment requirement: the README requires `OLLAMA_HOST=127.0.0.1`; the gateway is the only network-facing service. Not checked by the gateway at runtime. |
| Indirect injection | Instructions hidden in web pages, emails or database rows returned to the model | Tool results and disclosed values are scanned like user input (sections 4 and 5). |

## Signature feed format

```json
{
  "version": "2026-10-03.1",
  "source": "https://feeds.example.internal/ai-signatures",
  "sha256": "<hash of the signatures array>",
  "signatures": [
    {
      "id": "SIG-DESER-001",
      "category": "unsafe_deserialization",
      "severity": "high",
      "applies_to": ["input", "tool_result", "model_output", "tool_args"],
      "type": "regex",
      "pattern": "pickle\\.loads|cos\\nsystem|__reduce__",
      "reference": "CVE or advisory link where one exists"
    },
    {
      "id": "SIG-SUPPLY-004",
      "category": "supply_chain",
      "severity": "high",
      "applies_to": ["input", "tool_args", "url"],
      "type": "substring",
      "pattern": "trust_remote_code=True"
    }
  ]
}
```

`sha256` is the hex sha256 of the canonical JSON of the `signatures` array
(`json.dumps(signatures, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`,
UTF-8); `gateway.cli.fetch_feed.feed_sha256` computes it.

`applies_to` takes `input`, `tool_result`, `tool_definition`, `model_output`, `tool_args`
and `url`. Severity maps to action: `high` blocks, `medium` follows the control's mode, `low`
logs.

## Externally managed feed

`python -m gateway.cli.fetch_feed <url>` downloads a feed, verifies its `sha256`,
validates the schema and atomically replaces `signatures.json` (temp file, `os.replace`;
a rejected feed leaves the old file untouched). `--sha256` also checks the whole file
against a hash obtained out of band; the embedded hash alone only detects corruption. The gateway reloads it
like the policy. Every audit record stores the feed version, and the dashboard shows
which version blocked each request. At the hackathon the source is a local file; the
command shows how a security team's system would push updates.

## Model file scanner

`python -m gateway.cli.scan_model <path>` scans a model file or archive before it is
imported (for example before `ollama create` from a downloaded checkpoint). It reports
every imported global (`GLOBAL`, `INST`, `STACK_GLOBAL` resolved through the stack and
memo; extension-registry imports fail) and exits non-zero on anything outside the
allowlist, on known code-execution entry points inside allowed packages (for example
`numpy.testing` `runstring`, `torch.load`) and on anything it cannot parse. `_codecs` is
allowed because protocol 0-2 pickles store bytes through `_codecs.encode`. Nothing is ever
unpickled. Tests use two tiny fixtures: a safe pickle and one whose `__reduce__` calls `os.system`.
