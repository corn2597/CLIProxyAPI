# Risk Control E2E Evidence

This directory contains local validation artifacts for the moderation-based risk-control flow.

Current branch behavior no longer audits 100% of requests in a session.
The runtime now audits the first request for a session and reuses the last successful result within `session-audit-interval` (default `5m`).

- `01-observe-tab-before-actions.png`: Observe tab in `mode=observe` before labeling, including a hard-block moderation result stored in Observe.
- `02-observe-block-labeled.png`: Observe tab after clicking `BLOCK` for the hard-block sample.
- `03-observe-allow-labeled.png`: Observe tab after clicking `ALLOW` for the observe-only sample.
- `04-observe-logs.png`: Logs tab in `mode=observe`, showing `block` and `observe` decisions rendered in the frontend.
- `05-logs-100-percent-sampling.png`: Legacy evidence from the previous implementation that audited every request for the same session. Do not use it to validate the current branch behavior.
- `06-async-blocked-tab.png`: Blocked tab in `mode=async_block`, showing `ban_applied=yes` and `decision_source=fresh_audit` for `async-ban-unique`.
- `07-blocked-allow-once.png`: Blocked tab after clicking `Allow once` for `allow-once-unique`.
- `08-blocked-allow-session.png`: Blocked tab after clicking `Allow session` for `allow-session-unique`.
- `09-blocked-confirm-block.png`: Blocked tab after clicking `Confirm block` for `confirm-block-unique`.
- `10-async-blacklist-403.png`: Screenshot summary of the second request for `async-ban-unique` returning HTTP 403 after the async ban landed.

Supporting text artifacts:

- `async-ban-response.txt`: first async blacklist check summary.
- `async-ban-unique-response.txt`: final async blacklist check summary used for the screenshot.

Real OpenAI moderation validation artifacts:

- `real/01-real-observe.png`: Observe tab populated from live `https://api.openai.com/v1/moderations` results.
- `real/02-real-observe-logs.png`: Logs tab in `mode=observe`, showing live `block` and `observe` decisions.
- `real/03-real-observe-labeled.png`: Observe tab after live positive/negative sample labeling.
- `real/04-real-async-blocked.png`: Blocked tab in `mode=async_block`, showing a live async session ban with `ban_applied=yes`.
- `real/05-real-blocked-allow-once.png`: Blocked tab after live `Allow once` labeling.
- `real/06-real-blocked-allow-session.png`: Blocked tab after live `Allow session` labeling.
- `real/07-real-blocked-confirm-block.png`: Blocked tab after live `Confirm block` labeling.
- `real/08-real-logs-100-percent-sampling.png`: Legacy live evidence from the previous implementation that audited every request. Do not use it to validate the current branch behavior.
- `real/real-async-blacklist.txt`: Text proof that the second request for `metadata-session:real-async-ban` returned HTTP 403 after the async ban landed.

Session-interval smoke artifacts for the current branch are generated locally under `artifacts/session-interval-smoke/` during manual validation and are intentionally ignored by Git.
