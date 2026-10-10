"""Development and testing tools, outside the installable package.

Responsibility: scripts used to exercise Continuum during development.
None of this code ships as part of the continuum package and none of it
is a dependency of src/continuum.

Modules:
    attack_sketches.py  Documented, inert sketches of how keystroke
                         injection attacks behave, used as a reference for
                         writing realistic simulators and tests. Contains
                         no working exploit payloads.
    simulators.py       Generates synthetic KeyEvent streams at
                         configurable cadence (human-like or
                         injection-speed) for testing detection without
                         real hardware.
    data_generators.py  Builds synthetic baseline and incident datasets
                         for exercising detection, the connector and
                         IncidentRAG in tests and demos.
    capture_demo.py      Live terminal demo of the capture layer: per
                         device event rate and median inter-key interval,
                         no key content.
    record_baseline.py   Guided session that records a real baseline for
                         one keyboard, saved as FeatureWindow statistics
                         only, never the text that was typed.
    simulate_attacks.py  Five labelled, seeded cadence profiles (human,
                         burst_injection, slowed_injection,
                         randomized_injection, hybrid) used to train and
                         evaluate detection without real hardware.
    train_model.py        Fits and calibrates a CadenceModel from a
                         recorded baseline.
    evaluate_model.py     Evaluates a trained model against simulated
                         attacks and held-out human windows; writes
                         docs/eval_results.md and an ROC plot.
    run_hardware_trial.py Watches the incident outbox while the real
                         runtime is running against real Digispark
                         hardware, and records detection timing to
                         docs/hardware_trial_results.csv.
    attacks/              Harmless Digispark test payloads (one sketch
                         per cadence profile) and their own README for
                         building, flashing and safely running them.
    gen_incidents.py       Seeded, reproducible synthetic incident history
                         (150 to 300 records over 90 days) posted through
                         the connector API, so the whole ingest path runs.
    rag_cli.py             Ask IncidentRAG a question from the terminal,
                         in-process against the real Chroma collection
                         and Ollama instance; prints the answer,
                         confidence and citations.
"""
