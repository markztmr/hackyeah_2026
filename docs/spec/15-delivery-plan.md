# 15. Delivery plan

We plan for the earlier possible deadline and work in three tiers, timed as hours after the
official start (H0). Feature freeze is three hours before the deadline.

**Deadline.** The English competition terms say work starts no earlier than 11:00 PM on 3
October and submissions close at 11:00 PM on 4 October. Another source reports 11:00
AM. We treat the earlier time as binding and confirm with the organizers on Discord at H0.
The 50% phase-1 threshold means breadth across all five criteria beats depth in one.

## Hour 1: model test

Run 10 fixed prompts against `llama3.2` and `qwen2.5:3b` through Ollama's OpenAI-compatible endpoint with the `query_data` tool. Measure for each model: share of data
questions that call `query_data`, share of SQL that passes the validator, share of answers
that use the placeholder, and median latency. The best model becomes `models.answer`.

- [ ] Hour-1 model test, result recorded in README
- [ ] Repo skeleton, stub model, `pytest` running green on an empty suite
- [ ] Deadline confirmed with organizers

## Tier 1: MVP (H1 to H10)

- [ ] Auth and policy loader with reload, version hash and validation
- [ ] Masker (secrets, PII) and injection phrase list
- [ ] Signature feed matching on input, tool results and model output
- [ ] Proxy pass-through for plain chat
- [ ] Client tool authorization with argument rules
- [ ] `query_data` tool loop on the stub model
- [ ] SQL validator, authorizer (tables, columns, scope `self` and `all`), read-only executor
  with `set_authorizer`
- [ ] Placeholder-only disclosure and single-pass fill
- [ ] Deterministic output filter (secrets, PII, unbound placeholders)
- [ ] Basic budget and audit log
- [ ] Tests for every item above

## Tier 2: complete (H10 to H17)

- [ ] Real Ollama end to end
- [ ] Judge model with hardened prompt and `on_failure`
- [ ] History re-masking and issued-value cache
- [ ] Protected-value index in the output filter
- [ ] Dashboard with the panels in section 12, auto-refresh, CSV export
- [ ] Model allowlist with digest pinning; model file scanner
- [ ] Disclosure with labels for `allow` users; scope `department`
- [ ] Profiles and `GET /policy/effective`

## Tier 3: stretch

- [ ] Benchmark script and latency slide
- [ ] Scope enforcement by rewrite
- [ ] Separate aggregate permissions
- [ ] `fetch_feed` command
- [ ] Buffered SSE for `stream: true`
- [ ] Hash-chained audit log
- [ ] `all_denied_message`

## Freeze (deadline minus 3 hours)

- [ ] README with one-command start and test command
- [ ] Demo script for the four worked examples in section 4
- [ ] Full test run, output captured for the slides
- [ ] Recorded demo video as a backup
- [ ] Slides, at most 10, exported to PDF
- [ ] HackTribe submission: title, team name, members (1 to 6), description, slides PDF,
  repository link

## Slide outline (10 slides)

1. Problem and one-line answer
2. Architecture and trust boundary
3. One pipeline in ten steps
4. Deferred binding: Anna's example
5. Governed agency: blocked `send_email`
6. Policy and strictness profiles, live reload
7. Dashboard and audit
8. Test suite and OWASP coverage
9. Performance telemetry
10. Integration in one line and scalability path
