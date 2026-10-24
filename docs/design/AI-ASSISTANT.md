# Design: AI query assistant

Status: implemented, October 2026. An optional language model writes
queries ([QUERIES.md](../QUERIES.md)) from plain English. It only writes
them: the appliance checks each one, and nothing runs until someone presses
Run. No model is involved in collection, detection or anything that runs on
its own.

## Configuration

**Configuration → AI Assistant**, its own page; admins only. Off by default.

| Field | |
|---|---|
| enabled | the AI button appears in query bars |
| provider | `anthropic` (the Messages API) or `openai` (any OpenAI-compatible API: OpenAI, OpenRouter, Ollama, LM Studio, vLLM, llama.cpp) |
| URL | `https://api.anthropic.com` by default for Anthropic; e.g. `http://ollama.lan:11434/v1` |
| API key | optional for local servers; stored encrypted, never returned |
| model | chosen from a list the provider returns once the URL (and key) are set |
| send names | on by default: exporter, device, inventory and threat feed names go with the prompt so the model can write `host:waldorf`. Off sends only the language and the prompt. Flow data is never sent. |

TLS uses the appliance's trust store. Anthropic calls use the official Go
SDK with environment credentials disabled, so only the configured key is
ever used.

## Writing a query

```mermaid
sequenceDiagram
    participant U as Query bar
    participant A as Appliance
    participant M as Model
    U->>A: POST /api/ai/query {prompt}
    A->>M: system: language, fields, examples, names; user: prompt
    M-->>A: {query, range, explanation}
    A->>A: check the query (parser, fields, names)
    alt invalid (up to 2 retries)
        A->>M: the error and its hint
        M-->>A: corrected query
    end
    A-->>U: query, range, explanation, warnings
    Note over U: shown in the bar, not run
```

- The model answers JSON: `query`, `range` (one of the range bar's
  presets, or empty) and a one-line `explanation`. Anthropic models that
  support it get a JSON schema (structured outputs); others are asked for
  JSON and the answer is parsed leniently.
- A query that still fails after two corrections comes back with its error,
  so the bar shows what went wrong.
- Every request is audit-logged (who, prompt, resulting query). Requests
  are limited to 20 a minute per user and 150 seconds each: local models
  can be slow.

## Not in scope

- Running queries, summarizing traffic, or chatting about it: that is the
  security assistant's job, through MCP.
- Explaining a query in words: possible without a model (the parsed query
  is enough), and left for later.
