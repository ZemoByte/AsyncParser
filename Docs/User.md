# User.md — How to work with this user

## Who the user is
- Strong in cybersecurity and reverse engineering: PE format, .NET metadata, IL, obfuscation (ConfuserEx etc.), malware families, YARA, static analysis, dnSpyEx/ILSpy/dnlib.
- Beginner in machine learning and AI. Do not assume ML vocabulary.
- A student building a university project. You are inside Fedora VM and Host laptop with a 4GB RTX 3050.
- Learns best from analogies to reverse engineering and malware analysis.

## How to talk
1. Plain, concrete language. No hype, no filler, no motivational talk, no flattery.
2. Start every reply with a 1-2 sentence summary of what you did or found. Details after.
3. First time you use an ML term, define it in one sentence with a security analogy, then use it normally. Use the glossary below. If user says "did got it" explain wtih security analogies and similar terms in real world examples 
4. State a choice and the reason in one line each. Do not list five options unless asked. Recommend one.
5. If unsure, say "I am not sure" and say what you would check. Never guess names, APIs or flags. Run `--help` or read the code.
6. Never claim something works unless you ran it or a test proved it. Say "not tested" when it is not.
7. If the request conflicts with `Docs/Plan.md` or looks like a mistake, say so before doing it.
8. Keep answers short. Offer one next step at the end.
9. When asking questions (see Relentless Interviewing in `AGENTS.md`): at most 3 at a time, each with your recommended default.
10. Do not write long explanations in code comments. Put explanations in the chat reply.

## When the user asks an ML question
1. Answer in 2-3 sentences with a security analogy or real life similarity.
2. Show the smallest concrete example (a 5-row table or 5-line snippet).
3. Say what it means for this project. Then stop.

## When something fails
Give the exact error text, what you tried and your best guess. Do not hide it. Do not retry the same thing in a loop.

## Glossary (ML term → meaning in the user's world)
- **Feature**: one measurable property of a sample (e.g. "references TcpClient"). Like one YARA condition.
- **Feature vector**: all features of one sample as a list of numbers. Like a row of true/false YARA matches.
- **Label**: the correct answer for a sample (AsyncRAT or not). Like the family tag.
- **Training / validation / test set**: samples the model learns from / used for tuning / hidden for the final check. Like writing a rule on some samples and testing on others.
- **Data leakage**: test data secretly resembles training data, so scores look great but mean nothing. Like testing a YARA rule on the samples you wrote it from. Near-identical malware builds cause this.
- **Cluster**: a group of near-duplicate builds (same campaign). Kept together on one side of the split.
- **Cluster split / temporal split**: split by cluster or by date, so the test set contains new campaigns.
- **Model**: the function turning a feature vector into a prediction.
- **LightGBM**: many small if/else decision trees. Fast, runs on CPU, explainable.
- **kNN / nearest neighbor**: "find the most similar known sample and copy its label". Like TLSH or ssdeep matching against a database.
- **Baseline**: a simple method the real model must beat to prove it adds value.
- **Ablation**: remove or add one feature group at a time to see what it really contributes. Like disabling one YARA condition to see if the rule still works.
- **Overfitting**: the model memorized specific samples instead of general patterns.
- **Precision**: of the samples flagged, how many were truly AsyncRAT.
- **Recall**: of all true AsyncRAT samples, how many were caught.
- **F1 / PR-AUC**: single numbers combining precision and recall.
- **Confusion matrix**: table of what was predicted vs what it truly was. Shows which families get mixed up (e.g. AsyncRAT vs DcRat).
- **Abstain**: the model says "out of my coverage" instead of guessing. Like a YARA scanner that reports "unsupported file".
- **Coverage**: the share of samples the model did not abstain on. Always reported together with accuracy.
- **Vocabulary** (this project): the list of external references we track, built from training data only.
- **Minimum document frequency (MDF)**: drop a feature that appears in too few clusters. Removes campaign-specific noise.
- **IDF weighting**: down-weights very common features. Useful for neural models, useless for LightGBM.
- **Feature importance / SHAP**: which features pushed a prediction up or down. Our way to say "flagged because of these capabilities".
- **Embedding**: a list of numbers representing code or text so similar things sit close together. Not used for now.
- **Hyperparameter**: a training setting, not learned from data.
- **Two-stage model**: Stage 1 asks "RAT or benign?", Stage 2 asks "which family?".