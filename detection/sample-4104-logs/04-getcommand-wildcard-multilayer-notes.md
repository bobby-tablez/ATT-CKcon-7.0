# Analyst notes — `04-getcommand-wildcard-multilayer.log`

**Do not reveal until after the room has had a chance to read the raw log and
guess the pattern.** Paired live-demo raw log: `04-getcommand-wildcard-multilayer.log`.
Sigma rules this maps to:
`../sigma-rules/sigma-t1027010-wildcard-alias-iex.yml` (fires on the first
event via the Get-Command wildcard dispatch) and
`../sigma-rules/sigma-t1027010-reversed-string-decode.yml` (fires on the same
event via the reversal/decode idiom).

Event 1 (ScriptBlockId `ce6a616b-...`):
```
$e=(gcm ?e*x).Name;$b='<reversed base64, see raw log>';$d=-join ($b[-1..-($b.Length)]);& $e ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($d)))
```
- `gcm` is the built-in alias for `Get-Command`. `?e*x` (wildcard `?` = one
  char, `*` = zero or more) resolves to the command name "iex" —
  functionally identical goal to the `gal` (Get-Alias) variant in
  `01-wildcard-getalias-iex.log`, using the *other* cmdlet ATT&CK T1027.010
  and the STEEP#MAVERICK research explicitly call out (Get-Alias AND
  Get-Command are both abused interchangeably in the wild; a detection that
  only covers one is a known-incomplete rule — the shipped
  `sigma-t1027010-wildcard-alias-iex.yml` covers both).
- The payload string is reversed character-by-character
  (`$b[-1..-($b.Length)]`) before being reversed back at runtime and
  base64/UTF-16LE-decoded — a second, independent layer of obfuscation
  stacked on top of the wildcard dispatch trick, mirroring the layered-decode
  structure of the real eight-layer STEEP#MAVERICK stager (each layer here is
  scaled down to two for a legible demo; production stagers observed in the
  wild ran considerably deeper).

Event 2 (ScriptBlockId `64d019f0-...`), ~46ms later:
```
# SYNTHETIC-STAGE2-PLACEHOLDER :: lab-only :: no-live-payload
```
- Two ScriptBlockId values, same ProcessId, 46ms apart: this is exactly the
  "each layer gets its own 4104 event" behavior described in
  `guides/04-telemetry-detection-guide.md` Section 1.1 — Script Block
  Logging did the deobfuscation work for the analyst; nobody had to run the
  reversal/decode by hand to read the second-stage content.
- This event's ScriptBlockText is the plaintext of the decoded, un-reversed
  stage-2 payload: an inert placeholder comment, not a functional payload —
  and correctly the one block across all four sample logs that no Sigma rule
  in this kit fires on.

Used by: `guides/04-telemetry-detection-guide.md` Section 1.1.
