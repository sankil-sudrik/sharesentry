"""A minimal in-memory stand-in for `streamlit`, enough to execute app.py end to end in tests.

It records every call so tests can assert on what the user would see, and returns widget values
from `values` (by label) the way a user interacting with the page would.
"""

from __future__ import annotations


class Rerun(Exception):
    pass


class SessionState(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__


class FakeUpload:
    def __init__(self, name: str, data: bytes):
        self.name, self._data = name, data

    def getvalue(self) -> bytes:
        return self._data


class FakeStreamlit:
    def __init__(self):
        self.session_state = SessionState()
        self.values, self.clicked, self.calls = {}, set(), []
        self.sidebar = self

    # ------------------------------------------------------------- recording
    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return self
        return record

    def messages(self, kind: str):
        return [str(args[0]) for name, args, _ in self.calls if name == kind and args]

    def called(self, name: str, label=None):
        return [c for c in self.calls if c[0] == name and (label is None or (c[1] and c[1][0] == label))]

    # ------------------------------------------------------------- context managers
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    # ------------------------------------------------------------- layout
    def columns(self, spec):
        return [self] * (spec if isinstance(spec, int) else len(spec))

    def rerun(self):
        raise Rerun()

    # ------------------------------------------------------------- widgets
    def _pick(self, label, options, index=0):
        return self.values.get(label, options[index or 0])

    def radio(self, label, options, index=0, **kwargs):
        self.calls.append(("radio", (label, options), kwargs))
        return self._pick(label, list(options), index)

    def selectbox(self, label, options, index=0, **kwargs):
        self.calls.append(("selectbox", (label, options), kwargs))
        return self._pick(label, list(options), index)

    def multiselect(self, label, options=(), default=None, **kwargs):
        self.calls.append(("multiselect", (label, options), kwargs))
        return self.values.get(label, list(default or []))

    def text_input(self, label, value="", **kwargs):
        return self.values.get(label, value)

    text_area = text_input

    def checkbox(self, label, value=False, disabled=False, **kwargs):
        return False if disabled else self.values.get(label, value)

    def file_uploader(self, label, **kwargs):
        return self.values.get(label)

    def button(self, label, disabled=False, **kwargs):
        return label in self.clicked and not disabled

    form_submit_button = button

    def download_button(self, label, data, file_name=None, mime=None, **kwargs):
        assert isinstance(data, (str, bytes)), f"download '{label}' needs str/bytes"
        self.calls.append(("download_button", (label, data, file_name, mime), kwargs))
        return False
