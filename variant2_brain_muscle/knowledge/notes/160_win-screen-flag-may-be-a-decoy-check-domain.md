---
tags: anti-analysis flag-verification
source: distilled/flareon
---
The string shown at the obvious "win" screen can be a DECOY. FLARE-On 13 neon_outrun rendered `decode_this_system_to_win_it@f1are-on.com` at the finish line - the domain uses digit `1` for letter `l` (`f1are` != `flare`), so it is not the real flag, and the challenge text hinted at it ("a cruel statistical mirage"). Before declaring solved: verify the flag domain character by character, and be suspicious when the win path is trivially reachable. The real flag was on a HIDDEN code path (a native function registered into the engine but built from a different mechanism) - look for registered-but-unused handlers / branches the normal happy path never takes.
