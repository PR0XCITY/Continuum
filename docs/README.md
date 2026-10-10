# Continuum docs

This folder holds design notes and operator documentation that are too
long for the top-level README.md.

Current contents:

- `EVALUATION.md` and `figures/`: every measured result for the HID
  Firewall, IncidentRAG and the end-to-end path, with a Limitations
  section. Generated; regenerate with `python tools/evaluate_all.py`
  rather than editing by hand.
- `eval_results.md`: the single-model evaluation from
  `tools/evaluate_model.py`, shown on the dashboard's calibration page.
- `hardware_results.md`: a template for notes during Digispark trials.
- `windows_notes.md`: Windows-specific behaviour of the capture layer.

Suggested contents as the project grows:

- `architecture.md`: data flow from capture through detection, response,
  connector and RAG.
- `threat-model.md`: what Continuum defends against and what it does not.
- `runbook.md`: what to do when a device is blocked, how to release it,
  and how to read an incident record.

No em dashes or emoji in any file in this folder.
