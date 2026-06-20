---
title: Changelog
subtitle: Release history for ctrl-exec.
updated: 2026-06-20
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/CHANGELOG.md
current_page: /changelog
---

::: textbox
A high-level summary of released versions. The canonical, fuller changelog lives
in [`CHANGELOG.md`](https://github.com/OpenDigitalCC/ctrl-exec/blob/main/CHANGELOG.md)
in the repository, and the complete detail is in the git log. Unreleased work on
`main` may be ahead of the latest version below.
:::

0.11.1
: Built-in cert rotation - the agent handles dispatcher-serial rotation as a
  first-class control-plane operation. Clearer upgrade messaging and profile
  documentation.

0.10.1
: Packaging fixes for the compiled executor.

0.10.0
: Privilege separation and per-script security profiles - an unprivileged Perl
  front-end plus a small root C executor that applies a profile (run_as,
  capabilities, control dirs read-only) before exec.

0.9.3
: Clearer dispatch errors.

0.9.1
: Explicit `serve` mode for the agent.

0.9.0
: Native multi-dispatcher support and seamless cert rotation.

0.8.x
: The MCP bridge, async (detached) jobs, and the dispatcher/agent split.

0.7.x and earlier
: Early development - the core dispatch, mTLS, allowlist and pairing model.
