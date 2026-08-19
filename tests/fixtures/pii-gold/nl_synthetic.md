# Synthetic NL gold-set (no real PII). Stdlib scrub must catch these.
# NER tests run only when Presidio is importable (skip ≠ pass for merge gate).

## Contact

From: Jane Doe <jane.doe@example.invalid>
Phone: +31 6 12345678
IBAN: NL91 ABNA 0417 1643 00
BSN: 123456782
DOB: geboortedatum: 1990-05-17
Address: Teststraat 1, 1234 AB
MAC: 00:1A:2B:3C:4D:5E

| **Reporter** | Jane Doe |
| **DESCRIPTION** | Free text may still contain names after stdlib-only scrub. |
