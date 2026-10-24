# AI assistant

An optional language model writes queries ([QUERIES.md](QUERIES.md)) from
plain English: the **AI** button at the left of a query bar. The query goes
into the bar for you to check; nothing runs until you press Run. The
appliance checks every query the model writes and sends errors back to it
for correction (twice at most).

## Setting it up

**Configuration → AI Assistant** (administrators):

- **API:** *Anthropic* (Claude's Messages API, or a gateway's Anthropic
  endpoint) or *OpenAI-compatible* (OpenAI, OpenRouter, Ollama, LM Studio,
  vLLM, llama.cpp, gateways such as Bifrost or LiteLLM).
- **URL:** empty means `https://api.anthropic.com` for Anthropic. For
  OpenAI-compatible APIs, the base ending in `/v1`, e.g.
  `http://ollama.lan:11434/v1`. A gateway's Anthropic endpoint is usually
  `https://gateway/anthropic`.
- **API key:** stored encrypted, never shown again; local servers usually
  need none.
- **Model:** listed from the API once the URL and key are set; type to
  search. For Anthropic, `claude-opus-5-5` is chosen when offered.
- **Write a sample query** tries the settings before saving.

TLS uses the appliance's trusted certificates (Appliance → Certificates).

## What is sent

The model gets a description of the query language, examples, your prompt
and, unless **Send names** is off, the names of exporters, devices,
inventory objects and threat feeds, so it can write `host:waldorf`. Flow
data is never sent. Every prompt is in the audit log with the query it
produced.

## Choosing a model

Small models do well: in testing, Claude Haiku 5.5 wrote correct queries in
about two seconds, and a local 7B model (Qwen 2.5) also got them right, in
15–50 seconds on modest hardware.
