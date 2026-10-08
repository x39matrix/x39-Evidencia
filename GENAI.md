# Use of generative AI

This statement follows the NLnet generative AI policy (version 1.1).

**Tools.** Two tools are used, and no others:
- **Claude** (Anthropic): Claude Code in the development environment, and the Claude app for coordination.
- **Codex** (OpenAI).

**What they are used for:**
- drafting and translating texts;
- generating code, which the author reviews and tests;
- running tests and independent reproductions of results.

**How it is governed:**
- The human author decides the scope and the rules of each task.
- The author tests on real devices, deploys, and checks every output.
- Nothing a tool claims is taken as done until there is real output: a command that has only been written down does not count until it has been run and its result has been seen.
- Deployments, releases and signing keys stay in the author's hands.

**Marking.** From now on, commits that contain generated code or text state the model and version used and a summary of the prompts.

**Records.** The prompts and the outputs are kept.

Author: X39matrix.
