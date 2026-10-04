# AI Control Layer (HackYeah 2026)

OpenAI-compatible security gateway (`POST /v1/chat/completions`) between AI clients and an LLM.
See `CLAUDE.md` for commands and rules, and "AI Control Layer — Design Specification v2" for the design.

```bash
pip install -e ".[dev]"
pytest
```

## Run it locally

```bash
pip install -e ".[dev]"
python db/seed.py                      # creates demo.db
pytest                                 # stub model; no Ollama needed

ollama pull qwen2.5:3b                 # answer model (see "Model choice")
ollama pull qwen2.5:1.5b               # judge model
ollama run qwen2.5:3b "hi"             # warm it up; the first call after a cold start is slow
```

Then, in three terminals:

```bash
uvicorn gateway.main:app --port 8000                  # gateway on :8000
streamlit run demo_agent/app.py                       # chat as anna / marek / piotr
streamlit run dashboard/app.py --server.port 8501     # posture, live feed, totals, export
```

## Model choice

Hour-1 model test (spec section 15), `python scripts/model_bakeoff.py`, 2026-10-03:

| Model | Data questions calling `query_data` | SQL = single SELECT | Answers using the placeholder | Median latency (s) |
| --- | --- | --- | --- | --- |
| llama3.2 | 100% | 100% | 78% | 0.7 |
| qwen2.5:3b | 100% | 100% | 100% | 0.7 |

Through the real gateway (10 scenarios × 3 runs), qwen2.5:3b never wrote tool calls as
plain text (llama3.2: 4 times), answered the coding question every time (llama3.2: never)
and did not invent numbers. `models.answer` is `qwen2.5:3b`, and llama3.2 is no longer in
`models.allowed`: a request for it is blocked.
