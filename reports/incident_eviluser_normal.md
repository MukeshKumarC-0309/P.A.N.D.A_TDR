# Security Alert (Plain-Language) — DESKTOP-G38AOOL

**How serious:** URGENT — this is a confirmed break-in, not just a failed attempt.  
**Affected computer:** DESKTOP-G38AOOL  
**Account involved:** eviluser

## What happened

Someone using another computer (`10.0.2.3`) repeatedly tried to guess the password for the `eviluser` account on `DESKTOP-G38AOOL`, and eventually succeeded — they got in. After getting in, they created a new hidden account (`backdoor`) so they can come back later — even if you change the original password. This is a real break-in that already worked, so it needs attention right away.

## What this means for you

- The password for `eviluser` is no longer safe — the attacker knows it.
- They set up a hidden way back in (the `backdoor` account), so simply changing one password is not enough to lock them out.
- We do not have proof yet that they copied files or reached other computers — but we also cannot rule it out, so treat this computer as compromised until it has been checked.

## What to do now

1. **Disconnect `DESKTOP-G38AOOL` from the internet and network now** (unplug the cable / turn off Wi-Fi). This stops the attacker from doing more.
2. **Contact your IT support or a security professional** — tell them a computer was broken into and show them this alert.
3. **Have IT remove BOTH the `eviluser` and `backdoor` accounts** — do not just change the password, because the hidden account would still let the attacker back in.
4. **Ask IT to check this computer** for anything else that was changed or added.