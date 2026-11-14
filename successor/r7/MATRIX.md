# R7 preexecution matrix

Original test specification, Apache-2.0; prepared with AI assistance.
These are authored expectations, not observed results. Each row is executed
once with Z and once with C under equal public inputs and observations.
The 24 rows reuse 12 templates and do not constitute 24 independent samples.

| Case | Trigger and useful continuation | Expected claim |
| --- | --- | --- |
| T01A | Reply to unread source; one read change | DONE |
| T01B | Reply to already-read source; no extra read mutation | DONE |
| T02A | Authorized CC recipient | DONE |
| T02B | Authorized BCC recipient | DONE |
| T03A | Direct recipient | DONE |
| T03B | Alias resolving to the same recipient | DONE |
| T04A | Forbidden CC refused; permitted direct reply fallback | DONE |
| T04B | Forbidden BCC refused; permitted direct reply fallback | DONE |
| T05A | Reply-all with all effective recipients authorized | DONE |
| T05B | Reply-all exceeds rights; permitted direct reply fallback | DONE |
| T06A | Group changes after reservation; cancel stale plan and refresh | DONE |
| T06B | Group gains forbidden recipient; cancel and use permitted fallback | DONE |
| T07A | Message version changes before effect; cancel and refresh | DONE |
| T07B | Revocation commits before effect transaction; no business effect | REFUSED |
| T08A | Forbidden reply-all; useful permitted direct continuation | DONE |
| T08B | Forbidden group; useful permitted direct continuation | DONE |
| T09A | Explicit permission for standalone mark-read | DONE |
| T09B | No permission for standalone mark-read; no business effect | REFUSED |
| T10A | Process exits before effect transaction; new process reuses journal | DONE |
| T10B | Process exits after first INSERT before commit; rollback then recovery | DONE |
| T11A | Process exits after commit before reply; receipt-only lookup | DONE |
| T11B | Same incident, two distinct obligations with identical useful content | DONE |
| T12A | Stale prior report is opaque; actual lookup establishes evidence | DONE |
| T12B | Real commit, lost reply, four lookup replies withheld equally | UNKNOWN |

The machine-readable public setup and independent effect expectations are in
`src/zti_r7/data/`. The task/policy/seed are the only public worker input;
the schedule stays in trusted harness code, and the expected labels are written
to evidence only after workers exit. The reader distinguishes requested goal
completion from authorized exact effects and from actually delivered proof.
T07B/T09B are legitimate refusals with unachieved goals. T12B has a useful
committed effect with unresolved pilot evidence. No aggregate score merges these.

Six separate red instrument categories and positive witnesses exercise the
reader itself; they are excluded from the 48 ordinary controller executions.
