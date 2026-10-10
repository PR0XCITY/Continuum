# Post-incident review template

## When to use

Use this template after any confirmed attack, any incident where
commands may have executed, and any false positive that disrupted
users for more than a few minutes. A review is about learning, not
blame. Hold it within a week, while memories are fresh, and keep it
short enough that people actually finish it.

## Steps

1. Summary. Two or three sentences: what happened, on which
   workstation, and the final outcome. Include the Continuum incident
   id.
2. Timeline. List events in order with times: device first configured,
   detected_at, containment action, first human response, device
   removed, investigation closed. Use the incident record and the
   Windows event logs as sources.
3. Detection. Record the attack pattern, anomaly score, threshold and
   time to detect. State whether detection worked as designed, and if
   not, why not.
4. Response. Record what action_taken was and whether it matched the
   configured response mode. Note whether the auto-release timer, the
   unblock endpoint or the release-all command was used.
5. Impact. What commands ran, what data or credentials were exposed,
   and how many people were affected. Write "none found" only if the
   command review playbook was actually completed.
6. Root cause. How did the device get there? Physical access gap,
   social engineering, insider, or a legitimate device misjudged.
7. What went well. Name at least one thing worth keeping.
8. Actions. Each action gets an owner and a due date, for example
   updating the allowlist, enabling script block logging, or changing
   a physical access rule.
9. Follow-up. Schedule a short check one month later to confirm the
   actions were completed.

## Common mistakes

- Skipping the review because the attack was stopped quickly. A fast
  detection still means somebody had physical access to a machine.
- Writing actions without owners, which guarantees nobody does them.
- Turning the review into a search for someone to blame, which teaches
  people to report less next time.
- Leaving out false positives. They reveal tuning and allowlist
  problems just as clearly as real attacks reveal security gaps.
