# Lab 8: Password Strength

**Why it matters:** length helps only when the characters are hard to guess. Attackers try common words, keyboard runs, number sequences, and repeated patterns first, often with character substitutions such as `P@ssw0rd`.

## Exercise

Run `python3 -m labs.password_strength.estimate` from the repository root and enter a value at the hidden prompt. The estimator subtracts predictable segments from the length before rating it: common password words (including simple leet substitutions), runs of three or more keyboard, alphabet, or number characters, repeated characters, and a value that repeats one short pattern. It reports the remaining "unpredictable length" and the reasons for any deduction. Nothing is stored, logged, or sent.

Run `python3 -m labs.password_strength.estimate --samples` to rate the synthetic examples in `samples.txt`. Compare `Password123456789!` (18 characters, rated Weak) with `correct-horse-battery-staple`, then add your own synthetic examples to a copy of the file. Never put real passwords in a file.

This is a rough teaching heuristic, not an entropy calculation or breach check. Its word list is deliberately tiny, and a value it rates Strong can still be weak, for example a well-known phrase or a password reused across sites.

**Takeaway:** prefer long, unique passwords or passphrases generated and stored by a password manager, and enable MFA where available. Character-class rules alone do not make a password strong.
