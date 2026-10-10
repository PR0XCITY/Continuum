"""Building blocks for tools/evaluate_all.py, which writes docs/EVALUATION.md.

Modules:
    common.py      Markdown tables, summary statistics and figure saving.
    detector.py    HID Firewall: simulated attacks over several seeds,
                   feature ablation, and the false positive study.
    hardware.py    Real Digispark trials from docs/hardware_trial_results.csv.
    rag_eval.py    IncidentRAG: retrieval, the confidence gate, and (when a
                   local Ollama model is available) answers and citations.
    end_to_end.py  First injected keystroke to incident visible in the API
                   and retrievable by IncidentRAG, through the real code.
    report.py      Assembles the sections and the Limitations section.
"""
