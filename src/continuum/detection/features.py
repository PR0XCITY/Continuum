"""Feature extraction from windows of keystroke timing events.

Responsibility: convert a bounded window of KeyEvent records for one device
into a fixed-size numeric feature vector describing typing cadence (for
example inter-key interval mean/variance, press duration, burstiness and
debounce-filtered event rate). Operates purely on timestamps, event types
and counters; never touches key identity because none is available this
far from capture.
"""
