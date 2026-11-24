# AGENTS.md

Read this file first, then `Docs/User.md` (how to talk to the user) and `Docs/Plan.md` (what we decided and what to build).

## Core principles

### 1. Think Before Coding
**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First
**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: *"Would a senior engineer say this is overcomplicated?"* If yes, simplify.

### 3. Surgical Changes
**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

**Test:** every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution
**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

### 5. Memory (Engram)
All memories are committed to the `asyncparser` project in the Engram MCP. (if doesnt exists create it)

### 6. Relentless Interviewing
Stress-test plans and designs through systematic questioning:
- Conduct deep-dive questioning across all aspects of a plan, walking decision trees branch-by-branch until shared understanding is reached.
- Automatically explore the codebase to answer questions where code context is available.
- Designed for design reviews, architecture validation, and pre-implementation planning.
- Ask the questions in small batches (at most 3 at a time), each with your recommended default, so the user can answer "yes" to move on. See `Docs/User.md`.

### 7. No Commits Until Told
No commit to Engram memory or git (remote/local) until explicitly told. The user commits. Engram commit only on explicit authorization.

No git commit/push by the assistant; the user commits.

## Project rules

### 8. Project scope (do not change without asking)
This is a university project: a **static detector for AsyncRAT .NET client payloads** using capability-based features and similarity analysis.

- In scope: .NET AsyncRAT client payloads (the exe that runs on a victim).
- Out of scope (label and exclude, do not try to solve): droppers, loaders, PowerShell/VBS stagers, native (Go/C++) builds, dynamic analysis.
- Hardware: laptop with a 4GB RTX 3050. Classical ML first (LightGBM, TLSH nearest-neighbor).
- Detection is **capability-based**: features come from the *external* references in .NET metadata (TypeRef, MemberRef, AssemblyRef, ImplMap). Never use a sample's own type, method, field or user-string names as features. Obfuscators randomize them.
- Never use `is_dotnet` or any file-format column as a model feature.
- Design is **two-stage**: Stage 1 = RAT vs benign. Stage 2 = family. Stage 2 excludes packer, loader and campaign artifacts. Both stages may abstain.
- Splits are by **cluster** (TLSH distance + shared config keys) or by **date**, never random.
- Feature vocabularies and frequency filters are fitted on the **training split only**, and count **clusters**, not files.
- Labels: never trust MalwareBazaar tags alone. Verify with `rat_king_parser` (labeling time only, never a model feature).
- Reference archives (builder, server, stub, plugins) are reference material, never training data.

### 9. Safety (strict)
- NEVER execute, load, import, or build any malware sample or any builder, server or stub component. Static parsing only.
- NEVER generate or compile new AsyncRAT clients.
- No downloading samples. No network except package registries.
- Assume everything runs in an isolated VM with no network and no shared folders. If a step needs to run something from a sample, stop and ask.
- Do not delete user data or samples. Move rejects to a quarantine folder. Ask before deleting anything.
- Do not commit binaries (`*.exe`, `*.dll`, `*.zip`, `*.7z`, `*.p12`).

### 10. Working rules
- Read the relevant files before editing. Confirm a bug is real before fixing it.
- Match samples by sha256, never by filename.
- Use one class vocabulary everywhere. Reject unknown values.
- Report exact error text. No `except: pass` that hides failures.
- Tests use synthetic files (tiny fake zips, hand-made CSVs), never real malware.
- Never guess a file name, function name, library API or CLI flag. Run `--help`, read the code or read the docs.
- Never claim something works unless you ran it or a test proved it. Say "not tested" when it is not.
- Python 3.10+.
- End every task with: what changed, what you ran, what passed, what is not tested.

### 11. Where things live
- `Docs/Plan.md` — decisions, architecture, build order.
- `Docs/User.md` — how to talk to the user, glossary.