# Executive Summary: Scheduled Task That Downloads Code

**What I did.** During a practice threat hunt on a training cyber range, I found an attacker who set up a hidden task that downloaded and ran malicious code every time someone logged in. I turned that into a detection rule for Microsoft Sentinel, a tool that collects security logs.

**Why it matters.** A hunt finds an attack after it happens. A rule catches the same behavior automatically next time.

**What I tested.** I ran it on the logs from the attack, where I already knew the answer, and it found it. Then I ran it over five months of ordinary logs to see what else it flagged. It only fired on the training range's own test tasks, which were harmless.

**Why it isn't live.** I kept it as a tested query and didn't set it up as a live rule, because I didn't want to affect the cyber range environment or the tools the leads have in place.

**What this shows.** I can write and test a security search in KQL, and check it against real data for false alarms.

*Practice environment (cyber range), simulated scenario.*
