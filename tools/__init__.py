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
"""
