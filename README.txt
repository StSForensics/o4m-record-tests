O4M RECORD TESTS 2026 v1.0: TEST VECTORS FOR T3 AND T14a (DRAFT PACKAGE, 7 Nov 2026, revision b)

What this is
A small package of test vectors for two of the O4M Record Tests: T3 (chain walk per stream, requirement C3) and T14a (capture counters balance, requirement C14). It holds a reference verifier written in Python with the standard library only, a deterministic generator that rebuilds every vector byte for byte, 52 vectors with their expected verdicts and exit codes, a mutation-kill record, an ambiguity log and a list of proposed reason codes.
Specification: O4M Record Tests 2026 v1.0, DOI 10.5281/zenodo.23857888 (https://doi.org/10.5281/zenodo.23857888). Markdown source SHA-256 8758174e927e971391443ce9142f9c78bafad21ad52f63613d2443a422869d3d.

Status, plainly
This is a self-run. The verifier, the vectors and the mutation harness were written and run by one author, and nobody else has reproduced any result. Nothing here has been verified by anyone outside the editor. The specification is in development and is not an implementation-ready test suite.
This package holds a new reference verifier written from the requirement text. It is not RT-1, the editor's demonstration code mentioned in the specification, and RT-1 is not in this package. The cells for RT-1 in Annex B of the specification stay "not yet checked". MUTATION_RECORD.txt fills the matrix for this new verifier only.

Vector profile v0 is a choice, not a standard
The specification leaves the wire format open; one normative wire profile is planned for its next version. Every format decision these vectors depend on (JSON with JCS rules, one-based numbering, the zero genesis hash, the teardown shape, integer bounds, the reason codes) is a "vector profile v0" choice. Each one is listed in AMBIGUITY_LOG.txt with the reading taken and the vectors that would change. The reason codes are proposed, not normative (REASON_CODES_PROPOSED.txt).

Known limits kept as vectors
t3-012: if a record is altered and every record after it is recomputed, the chain walk returns PASS. A chain walk alone cannot detect a full rewrite from the point of tampering. External commitments made before the rewrite (checkpoints with independent time-stamps and witnesses, C6 and T6a) are needed.
t14a-011: if the operator consistently under-reports what it received, the counters still balance and T14a returns PASS. Only reconciliation against a count the operator does not control (T14c) can show this.
t3-006 (an open stream's tail cannot be checked by T3 alone) is a third limit of the same kind.

How to run
Python 3, no packages to install. On a Mac type python3 instead of python; on Windows, python or py. Every vector has been run with Python 3.11, 3.12 and 3.13 on Linux, with identical results. The code is written for Python 3.8 or later, but 3.8 to 3.10 have not been run, and Windows and macOS have not been run. From this folder:
  python verify.py T3 vectors/T3/t3-001/input.json
  python verify.py T14a vectors/T14a/t14a-003/input.json
  python verify.py T14a vectors/alt-readings/alt-b-002/input.json --reading B
Exit code 0 is PASS, 1 FAIL, 2 HOLD, 3 a usage error, a file that cannot be read, or an internal error (no verdict). A crash never exits with 1. Each vector folder holds input.json, expected.txt (the exact verdict text), expected_exit.txt, about.txt (scenario, attack modelled, expected result and why) and intent.txt (the command and the result the author intended before running the verifier).
To check the package as shipped, first:
  sha256sum -c SHA256SUMS                 (on a Mac: shasum -a 256 -c SHA256SUMS; every line should say OK)
To rebuild and re-test everything:
  python gen_vectors.py . --expected      (rebuilds inputs and expected outputs; stops on any mismatch with intent)
  python mutation/mutate.py               (runs every mutant against every vector, rewrites MUTATION_RECORD.txt)
mutate.py writes the date, time and Python version of your run at the top of MUTATION_RECORD.txt, so after you run it that one file no longer matches SHA256SUMS. Every other file should still match. Compare the mutant lines, not the header.
Extract the zip rather than copying vectors by hand. The evidence hash in every verdict is the SHA-256 of the input.json bytes, so a changed line ending changes every expected verdict. The file .gitattributes stops Git from rewriting line endings. The zip file's own hash is not reproducible (zip stores timestamps); SHA256SUMS is the reference.

Alternative readings
vectors/alt-readings holds vectors for competing readings of "counters balance" and of declared gaps (Readings B, C and D). They are not the primary reading. AMBIGUITY_LOG.txt entries 18 and 20 give the author's recommendation on each.

For regulators, supervisors and anyone handed AI records
REGULATOR_QUESTIONS.txt indexes the vectors by three questions: is the record complete for the declared scope, who else holds a copy or a count, and how would a missing or changed entry be noticed. It also lists what these vectors cannot show. It is a reading aid, not guidance and not legal advice, and it changes no vector.

Second reader
SECOND_READER_PACKET holds what an independent second implementer should get: instructions, the published specification, and the vector inputs to hand over only after they have written their own verifier. It contains no reference code and no expected outputs. A second reader from the same AI vendor as the author is weak evidence; a different vendor or a human is better. Agreement counts show agreement only.

Disclaimer and terms of use
1. This package is free. It is provided AS IS, WITHOUT WARRANTY OF ANY KIND, under the Apache License 2.0 (sections 7 and 8 of that licence apply). Like any software it can contain errors; check anything important another way too.
2. A verdict from verify.py is an unsigned comparison of an input against the draft tests under vector profile v0. It is not a finding of fact, a rating of any company, a certificate, an assurance or an approval, and it should not be your only basis for a legal, financial, safety or regulatory decision.
3. Using this package does not create a client, adviser, expert or other professional relationship with StS Forensics Ltd (company 17054694) or Gareth Wong. StS Forensics Ltd has not yet started trading.
4. To the fullest extent the law allows, StS Forensics Ltd, its director and contributors are not liable for any loss arising from use of, or reliance on, this package. Nothing here limits liability for death or personal injury caused by negligence, for fraud or fraudulent misrepresentation, or for anything else the law does not allow to be limited. If you are a consumer, your legal rights are not affected.
5. Every input in vectors/ is made up for testing. None is a record of a real person, company or AI system.
6. The names O4M, O4M Record Tests, VerZan and StS Forensics are not licensed for use as trade marks (Apache-2.0 section 6).
7. Not legal advice. English law applies and the courts of England and Wales have jurisdiction, subject to any mandatory rights you have where you live.

Licences
Reference verifier, generator, mutation harness and test vectors: Apache License 2.0 (LICENSE, NOTICE). Requirement and test text quoted from the specification: Creative Commons Attribution 4.0 International (CC BY 4.0). Contributions are accepted under the same licences with a Developer Certificate of Origin sign-off.
Repository for issues, downloads and DCO-signed contributions: https://github.com/StSForensics/o4m-record-tests (releases: https://github.com/StSForensics/o4m-record-tests/releases)

Patents
STS Forensics Ltd does not assert patent rights against anyone who implements, runs or publishes results of these tests. Gareth Wong is named inventor on unpublished UK patent applications filed in early 2026 on hardware gating and logging, and will not assert any patent arising from them against implementing, running or publishing results of this suite. Third-party patents may exist; no assessment has been made. This is not legal advice. Results are published unsigned and no certificates are issued.

Name use
Any public statement about a run should quote the version, the T1b strength line and the in-scope tests not run, for example: "O4M Record Tests 2026 v1.0, Profile F: declaration 3 consequential action types, fail-closed, skew 5 s; C2 to C5 PASS; C14 and C22 not run; declared gaps: none." Please do not describe a system as "compliant", "conformant", "approved" or "certified" on the strength of these tests. Every verdict here is an unsigned result.

AI-assistance disclosure
The editor used AI assistants (Claude, by Anthropic) to help draft and edit requirement text, to search and summarise sources, and to write parts of the demonstration code. The editor reviewed the output and takes responsibility for it.
The reference verifier, vectors and mutation harness in this package were generated by an AI assistant from the requirement text above and are not yet reviewed or reproduced by anyone else.

Comments
Send comments to comments@sts-forensics.com with the subject "O4M Record Tests". Comments and the editor's replies are kept in a public comment log.
Public comment log: TO BE ADDED BY EDITOR (URL)

Copyright 2026 Gareth Wong.
