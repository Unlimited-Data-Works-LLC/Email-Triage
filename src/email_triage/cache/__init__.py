"""Optional caching surfaces for email-triage (#151).

Currently a single submodule (``classification``) — the optional
Redis-backed cache for LLM classification results. Future caches
(per-provider rate-limit metadata, message-id-seen-set, etc.)
should live alongside as siblings here, sharing the same opt-in
+ HIPAA-gate posture.

Nothing is re-exported at the package level by design: callers
must reach for the specific submodule + helper so the import
graph stays obvious. Lazy ``redis`` import lives in
``classification`` — importing ``email_triage.cache`` itself is
free of optional-dep weight.
"""
