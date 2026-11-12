# Model used for discovery

- Model: Claude Opus 5.5 (as displayed in the model selector)
- Provider / interface: Anthropic, claude.ai web chat
- Date: 2026-11-12
- Settings:
  - Effort: Médio (default)
  - Mode: Manual (as displayed, unchanged)
  - Search and reference past chats: off
  - Generate memory from chats: off
  - Custom instructions: none
  - Project: none
  - Web search, connectors and tools: off
  - Temperature: not controllable in the web interface
- Input per condition: only baseline_secure_coding_api.py attached + condition prompt
- Each condition (A, B, C) run in a fresh conversation, single request, no follow-ups.