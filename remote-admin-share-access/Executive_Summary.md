# Executive Summary: Remote Admin Share Access

**What I did.** During a practice threat hunt on a training cyber range, I found an attacker who used a stolen account to open an administrative file share on the company's main server, seconds before planting a malicious program. I turned that into a detection rule for Microsoft Sentinel, a tool that collects security logs.

**Why it matters.** A hunt finds an attack after it happens. A rule catches the same behavior automatically next time.

**What I tested.** I ran it on the logs from the attack, where I already knew the answer, and it found it. Then I ran it over months of ordinary logs to see what else it flagged. It was noisy. It flagged accounts and a computer address that also appear in the attack, so I can't just trust them. That told me the rule needs another condition before it could be used to alert.

**Why it isn't live.** I kept it as a tested query and didn't set it up as a live rule, because I didn't want to affect the cyber range environment or the tools the leads have in place.

**What this shows.** I can write and test a security search in KQL, and I can tell when a rule is too noisy to trust.

*Practice environment (cyber range), simulated scenario.*
