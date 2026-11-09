"""Punch 774 + 442: ``parse_ics`` returns one safe mailbox or nothing, and the readers of its dict are known.

774 (class AI DA S4, probe 2026-11-02 on icalendar 7.3.0): a lone CR, a NUL, a TAB or an address
list survived into ``attendees[].email`` and ``organizer``, and ``SEQUENCE:99999999999`` was not
clamped. The sink walk (the enumeration the fix started from):

* ``Attachment.parsed`` (the ``parse_ics`` dict) is read only by ``actions/invite.py``. It reads
  ``uid``, ``organizer``, ``summary`` and ``sequence``; ``organizer`` becomes the ``To:`` of the
  iMIP draft. It never reads ``attendees``.
* ``providers/gmail_calendar.py:446`` reads ``CalendarEvent.attendees``, which comes from the
  calendar API and from the agent API body, not from ``parse_ics``. Punch 823 closes that second
  source: see the "823" section at the bottom.

So the parser is the one place to refuse. These pins hold the funnel (every address leaves
``parse_ics`` through ``_cal_address_email``), the clamp, and the SET of readers of the dict, so a
new reader forces a decision about which fields it takes.

442: the parse paths the suite never exercised on the icalendar 7.1.2 -> 7.3.0 bump (attendee
params, ORGANIZER, METHOD, SEQUENCE, folded lines, TZID, first-VEVENT-wins, malformed input).
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone

import pytest

from _pin_harness import assert_pin_has_teeth, relpath, walk_src

from email_triage.engine import ics as ics_mod
from email_triage.engine.ics import parse_ics

# Readers of the parse_ics dict. A new entry means: confirm the fields it takes are the cleaned
# ones, and that no address field reaches an outbound surface by another route.
_PARSED_READERS = {"actions/invite.py"}

_HEAD = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{cal}BEGIN:VEVENT\r\nUID:u1@x.invalid\r\n"
_TAIL = "END:VEVENT\r\nEND:VCALENDAR\r\n"
_TIMES = "DTSTART:20261105T100000Z\r\nDTEND:20261105T110000Z\r\n"


def _ics(extra: str, cal: str = "") -> bytes:
    return (_HEAD.format(cal=cal) + _TIMES + extra + _TAIL).encode("utf-8")


# ---------------------------------------------------------------------------
# 774: the funnel refuses
# ---------------------------------------------------------------------------

_HOSTILE = [
    "a@x.invalid\rBcc: evil@x.invalid",        # lone CR mid-value
    "a@x.invalid\r",                            # trailing lone CR (a strip() would eat it)
    "a@x.invalid\r\n \rBcc: evil@x.invalid",    # CR behind a fold
    "a@x.invalid\x00b",                         # NUL
    "a@x.invalid\tb",                           # TAB
    "a@x.invalid, b@x.invalid",                 # address list
    "a@x.invalid;b@x.invalid",
    "Evil <a@x.invalid>",                       # display-name form
    "a@x.invalid b",                       # Unicode line separator
    "a@x.invalid\x85b",                         # NEL (C1)
]


@pytest.mark.parametrize("addr", _HOSTILE)
def test_a_hostile_address_is_refused_for_organizer_and_attendee(addr):
    blob = _ics(f"ORGANIZER:mailto:{addr}\r\nATTENDEE:mailto:{addr}\r\nATTENDEE:mailto:ok@x.invalid\r\n")
    parsed = parse_ics(blob)
    assert parsed is not None
    assert parsed["organizer"] == "", "a refused organizer is empty so invite.py falls back to the sender"
    assert [a["email"] for a in parsed["attendees"]] == ["ok@x.invalid"], "the hostile attendee is dropped, the good one kept"


def test_a_good_address_survives_with_its_params():
    parsed = parse_ics(_ics(
        'ORGANIZER;CN=Boss:MAILTO:Boss@X.invalid\r\n'
        'ATTENDEE;CN="Jo Q";PARTSTAT=ACCEPTED;ROLE=CHAIR:mailto:jo@x.invalid\r\n'
    ))
    assert parsed["organizer"] == "Boss@X.invalid"
    assert parsed["attendees"] == [{
        "email": "jo@x.invalid", "name": "Jo Q", "response_status": "accepted", "role": "CHAIR",
    }]


def test_mailto_is_stripped_case_insensitively_and_only_as_a_prefix():
    parsed = parse_ics(_ics("ATTENDEE:MailTo:a@x.invalid\r\nATTENDEE:mailto:b@mailto:x.invalid\r\n"))
    assert [a["email"] for a in parsed["attendees"]] == ["a@x.invalid", "b@mailto:x.invalid"]


@pytest.mark.parametrize("raw, want", [
    ("99999999999", 2147483647),
    ("2147483647", 2147483647),
    ("2147483648", 2147483647),
    ("-5", 0),
    ("abc", 0),
    ("7", 7),
])
def test_sequence_is_clamped_to_the_rfc5545_integer_range(raw, want):
    assert parse_ics(_ics(f"SEQUENCE:{raw}\r\n"))["sequence"] == want


def test_the_max_sequence_is_the_rfc_5545_integer_ceiling():
    assert ics_mod._MAX_SEQUENCE == 2147483647  # RFC 5545 section 3.3.8: -2147483648 to 2147483647


# ---------------------------------------------------------------------------
# 774: the structural pins
# ---------------------------------------------------------------------------

def _hand_rolled_mailto_strips(tree: ast.AST) -> list[int]:
    """Lines of ``<expr>.replace("mailto:", ...)``: the idiom the funnel replaced."""
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "replace"
        and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)
        and n.args[0].value.lower() == "mailto:"
    ]


def test_no_src_file_strips_mailto_by_hand():
    offenders = {rel: lines for _p, rel, tree in walk_src() if (lines := _hand_rolled_mailto_strips(tree))}
    assert not offenders, (
        f"a hand-rolled mailto strip returns an unchecked address; route it through "
        f"engine/ics.py::_cal_address_email: {offenders}"
    )


def test_the_mailto_detector_has_teeth():
    assert_pin_has_teeth(
        lambda t: _hand_rolled_mailto_strips(t),
        'x = str(p).replace("MAILTO:", "")', 'x = _cal_address_email(p)',
    )


def _address_property_reads_bypassing_the_funnel(tree: ast.AST) -> list[int]:
    """In ics.py: a ``.get("ORGANIZER"|"ATTENDEE")`` whose enclosing function never calls the funnel."""
    funnel_users = {
        fn for fn in ast.walk(tree) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(c, ast.Name) and c.id in {"_cal_address_email", "_attendee_dict"}
                for c in ast.walk(fn))
    }
    bad: list[int] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for c in ast.walk(fn):
            if (isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "get"
                    and c.args and isinstance(c.args[0], ast.Constant)
                    and c.args[0].value in {"ORGANIZER", "ATTENDEE"} and fn not in funnel_users):
                bad.append(c.lineno)
    return bad


def test_every_address_property_read_in_ics_py_goes_through_the_funnel():
    trees = {rel: tree for _p, rel, tree in walk_src("engine") if rel == "engine/ics.py"}
    assert trees, "engine/ics.py was not walked"
    assert not _address_property_reads_bypassing_the_funnel(trees["engine/ics.py"])


def test_the_funnel_bypass_detector_has_teeth():
    bad = 'def f(c):\n    return str(c.get("ORGANIZER"))\n'
    good = 'def f(c):\n    return _cal_address_email(c.get("ORGANIZER"))\n'
    assert_pin_has_teeth(_address_property_reads_bypassing_the_funnel, bad, good)


def _parsed_attribute_readers(tree: ast.AST) -> list[int]:
    return [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == "parsed"]


def test_the_readers_of_the_parse_ics_dict_are_the_known_set():
    """``Attachment.parsed`` has one reader today. A second one is a new sink to walk (punch 774)."""
    readers = {rel for _p, rel, tree in walk_src() if _parsed_attribute_readers(tree)}
    readers -= {"engine/models.py"}  # the dataclass docstring/field, not a read
    assert readers == _PARSED_READERS, (
        f"new reader(s) of the parse_ics dict: {sorted(readers - _PARSED_READERS)} "
        f"(gone: {sorted(_PARSED_READERS - readers)}). Walk the new sink: which fields does it take, "
        f"and do they all come out of engine/ics.py::_cal_address_email? Then update _PARSED_READERS."
    )


def test_the_reader_detector_has_teeth():
    assert_pin_has_teeth(_parsed_attribute_readers, "x = att.parsed['attendees']", "x = att.filename")


def test_invite_py_takes_no_attendee_field_from_the_dict():
    """invite.py reads uid/organizer/summary/sequence; an ``attendees`` read there is a new sink."""
    tree = next(t for _p, rel, t in walk_src("actions") if rel == "actions/invite.py")
    keys = {
        n.args[0].value for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
        and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)
    }
    assert "attendees" not in keys, "invite.py now reads parsed['attendees']: walk that sink (punch 774)"


# ---------------------------------------------------------------------------
# 442: the parse paths the suite skipped, asserted on real fields
# ---------------------------------------------------------------------------

def test_method_sequence_and_a_full_attendee_set_round_trip():
    parsed = parse_ics(_ics(
        "SEQUENCE:3\r\nORGANIZER;CN=Boss:mailto:boss@x.invalid\r\n"
        "ATTENDEE;PARTSTAT=TENTATIVE;ROLE=OPT-PARTICIPANT:mailto:a@x.invalid\r\n"
        "ATTENDEE:mailto:b@x.invalid\r\n",
        cal="METHOD:REQUEST\r\n",
    ))
    assert parsed["method"] == "REQUEST"
    assert parsed["sequence"] == 3
    assert parsed["organizer"] == "boss@x.invalid"
    assert [(a["email"], a["response_status"], a["role"]) for a in parsed["attendees"]] == [
        ("a@x.invalid", "tentative", "OPT-PARTICIPANT"),
        ("b@x.invalid", "needs-action", "REQ-PARTICIPANT"),
    ]


def test_a_tzid_start_is_converted_to_utc():
    parsed = parse_ics(
        (_HEAD.format(cal="") + "DTSTART;TZID=America/New_York:20261105T090000\r\n"
         "DTEND;TZID=America/New_York:20261105T100000\r\n" + _TAIL).encode()
    )
    assert parsed["start"] == datetime(2026, 11, 5, 14, 0, tzinfo=timezone.utc)  # EST is UTC-5 after 11-01
    assert parsed["end"] == datetime(2026, 11, 5, 15, 0, tzinfo=timezone.utc)
    assert parsed["all_day"] is False


def test_a_folded_summary_is_unfolded_and_a_str_blob_parses():
    text = _ics("SUMMARY:Quarterly planning\r\n  review for the whole team\r\n").decode()
    assert parse_ics(text)["summary"] == "Quarterly planning review for the whole team"


def test_the_first_vevent_wins():
    blob = (_HEAD.format(cal="") + _TIMES + "SUMMARY:first\r\n" + _TAIL.replace("END:VCALENDAR\r\n", "")
            + "BEGIN:VEVENT\r\nUID:u2@x.invalid\r\nSUMMARY:second\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n").encode()
    parsed = parse_ics(blob)
    assert (parsed["uid"], parsed["summary"]) == ("u1@x.invalid", "first")


@pytest.mark.parametrize("blob", [b"", b"not a calendar", b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"])
def test_input_with_no_event_parses_to_none(blob):
    assert parse_ics(blob) is None


def test_the_every_returned_key_is_present_on_a_minimal_event():
    parsed = parse_ics(_HEAD.format(cal="").encode() + _TAIL.encode())
    assert set(parsed) == {
        "uid", "summary", "description", "location", "start", "end", "all_day",
        "organizer", "attendees", "method", "sequence",
    }
    assert parsed["start"] is None and parsed["end"] is None and parsed["attendees"] == []


# ---------------------------------------------------------------------------
# 823: the calendar-write attendee sinks (the client-supplied source of the 774 class)
# ---------------------------------------------------------------------------
#
# 774 fixed the ICS source. The agent API takes attendees too: POST .../calendar/events builds a
# CalendarEvent from the request body, and PATCH .../calendar/events/{id} forwards the body as the
# provider's own JSON. Both reached gmail_calendar._serialize / update_event and the Graph twins with
# no check, so "a@x.invalid, b@x.invalid" or a CR/LF would address a second recipient.
#
# The fix funnels at the SINK (every concrete calendar provider), whatever the source, and the agent
# API answers 400 first so the caller learns an address was refused. These pins hold both halves.

_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
_ATTENDEE_FUNNELS = frozenset({"attendee_mailboxes", "native_attendees_safe"})
# engine/ics.py is the funnel's home (the 774 pins above cover it).
_ATTENDEE_SCAN_SKIP = frozenset({"engine/ics.py"})

# Every function in src/ that touches an attendee list, and what it does with it. "sink" sends
# attendees to a provider (or guards the call that does) and must call a funnel. The rest never send a
# caller-supplied address anywhere: "ingest" parses a provider response, "echo" hands a provider-read
# list back to the same provider (dropping an entry there would REMOVE an attendee, so it must not
# filter), "readout" returns the list to the caller, "empty" passes a literal [].
_ATTENDEE_TOUCHES = {
    ("providers/gmail_calendar.py", "_normalise"): "ingest",
    ("providers/gmail_calendar.py", "_serialize"): "sink",
    ("providers/gmail_calendar.py", "update_event"): "sink",
    ("providers/gmail_calendar.py", "respond_to_invite"): "echo",
    ("providers/office365_calendar.py", "_normalise"): "ingest",
    ("providers/office365_calendar.py", "_serialize"): "sink",
    ("providers/office365_calendar.py", "update_event"): "sink",
    ("web/routers/agent_api.py", "calendar_create"): "sink",
    ("web/routers/agent_api.py", "calendar_update"): "sink",
    ("web/routers/agent_api.py", "_serialize_event"): "readout",
    ("web/routers/agent_api.py", "_shape_calendar_event"): "readout",
    ("actions/self_sent_event.py", "execute"): "empty",
}


def _own_nodes(fn):
    """Nodes of fn that are not inside a nested function (those belong to the nested one)."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _FUNCS):
            stack.extend(ast.iter_child_nodes(node))


def _touches_attendees(node: ast.AST) -> bool:
    return (
        (isinstance(node, ast.Attribute) and node.attr == "attendees")
        or (isinstance(node, ast.Constant) and node.value == "attendees")
        or (isinstance(node, ast.keyword) and node.arg == "attendees")
    )


def _calls_a_funnel(fn) -> bool:
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _ATTENDEE_FUNNELS
        for n in _own_nodes(fn)
    )


def attendee_touchers(tree: ast.AST) -> list[tuple[str, int]]:
    """(function name, line) of every function that reads, builds or passes an attendee list."""
    return [
        (fn.name, fn.lineno) for fn in ast.walk(tree)
        if isinstance(fn, _FUNCS) and any(_touches_attendees(n) for n in _own_nodes(fn))
    ]


def sinks_without_a_funnel(tree: ast.AST, sinks: set[str]) -> list[str]:
    return [
        fn.name for fn in ast.walk(tree)
        if isinstance(fn, _FUNCS) and fn.name in sinks and not _calls_a_funnel(fn)
    ]


def _is_calendar_provider(cls: ast.AST) -> bool:
    return isinstance(cls, ast.ClassDef) and any(
        getattr(b, "id", getattr(b, "attr", None)) == "CalendarProvider" for b in cls.bases
    )


def calendar_provider_write_gaps(tree: ast.AST) -> list[str]:
    """In a class deriving from CalendarProvider: update_event must call native_attendees_safe, and a
    class with create_event must call attendee_mailboxes somewhere (its body builder)."""
    gaps = []
    for cls in ast.walk(tree):
        if not _is_calendar_provider(cls):
            continue
        methods = {m.name: m for m in cls.body if isinstance(m, _FUNCS)}
        called = {
            n.func.id for m in methods.values() for n in _own_nodes(m)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        if "update_event" in methods and "native_attendees_safe" not in called:
            gaps.append(f"{cls.name}.update_event forwards the partial without native_attendees_safe")
        if "create_event" in methods and "attendee_mailboxes" not in called:
            gaps.append(f"{cls.name}.create_event never builds attendees through attendee_mailboxes")
    return gaps


def test_the_attendee_touching_functions_are_the_known_set():
    """A new function that touches an attendee list is a new sink to classify (punch 823)."""
    found = {
        (rel, name) for _p, rel, tree in walk_src() if rel not in _ATTENDEE_SCAN_SKIP
        for name, _line in attendee_touchers(tree)
    }
    assert found == set(_ATTENDEE_TOUCHES), (
        f"new attendee-touching function(s): {sorted(found - set(_ATTENDEE_TOUCHES))} "
        f"(gone: {sorted(set(_ATTENDEE_TOUCHES) - found)}). Does it send an address to a provider? "
        f"Then it calls attendee_mailboxes / native_attendees_safe; add it to _ATTENDEE_TOUCHES."
    )


def test_every_attendee_sink_calls_a_funnel():
    sinks_by_file: dict[str, set[str]] = {}
    for (rel, name), kind in _ATTENDEE_TOUCHES.items():
        if kind == "sink":
            sinks_by_file.setdefault(rel, set()).add(name)
    assert sinks_by_file, "no sink is registered: the pin is blind"
    offenders = {}
    for _p, rel, tree in walk_src():
        if rel in sinks_by_file and (bad := sinks_without_a_funnel(tree, sinks_by_file[rel])):
            offenders[rel] = bad
    assert not offenders, f"attendee sink(s) that send a list without the 823 funnel: {offenders}"


def test_every_calendar_provider_guards_its_writes():
    seen = 0
    gaps: dict[str, list[str]] = {}
    for _p, rel, tree in walk_src():
        if found := calendar_provider_write_gaps(tree):
            gaps[rel] = found
        seen += sum(
            1 for c in ast.walk(tree) if _is_calendar_provider(c)
            and any(isinstance(m, _FUNCS) and m.name == "update_event" for m in c.body)
        )
    assert seen, "no concrete CalendarProvider was walked: the pin is blind"
    assert not gaps, f"a calendar provider writes attendees without the funnel: {gaps}"


def test_the_attendee_detectors_have_teeth():
    assert_pin_has_teeth(attendee_touchers, "def f(ev):\n    return ev.attendees\n", "def f(ev):\n    return 1\n")
    assert_pin_has_teeth(attendee_touchers, "def f(p):\n    p['attendees'] = []\n")
    assert_pin_has_teeth(
        lambda t: sinks_without_a_funnel(t, {"s"}),
        "def s(ev):\n    return [a['email'] for a in ev.attendees]\n",
        "def s(ev):\n    return attendee_mailboxes(ev.attendees)\n",
    )
    bad_provider = (
        "class P(CalendarProvider):\n"
        "    async def update_event(self, i, partial):\n        await self._request('PATCH', i, json_data=partial)\n"
        "    async def create_event(self, ev):\n        return [a for a in ev.attendees]\n"
    )
    good_provider = (
        "class P(CalendarProvider):\n"
        "    async def update_event(self, i, partial):\n"
        "        if not native_attendees_safe(partial.get('attendees', [])):\n            raise ValueError\n"
        "    async def create_event(self, ev):\n        return attendee_mailboxes(ev.attendees)\n"
    )
    assert_pin_has_teeth(calendar_provider_write_gaps, bad_provider, good_provider)


_HOSTILE_ADDRESSES = [
    "a@x.invalid, b@x.invalid",
    "a@x.invalid;b@x.invalid",
    "a@x.invalid\r\nBcc: c@x.invalid",
    "a@x.invalid\rb@x.invalid",
    "a@x.invalid\nb@x.invalid",
    "a@x.invalid\x00",
    " a@x.invalid",
    "a@x.invalid ",
    "<a@x.invalid>",
    "Name <a@x.invalid>",
    "",
    "mailto:",
]


@pytest.mark.parametrize("addr", _HOSTILE_ADDRESSES)
def test_attendee_mailboxes_drops_a_hostile_address(addr):
    assert ics_mod.attendee_mailboxes([{"email": addr}, {"email": "ok@x.invalid"}]) == ["ok@x.invalid"]


@pytest.mark.parametrize("entries", [
    None, "a@x.invalid", {"email": "a@x.invalid"}, [{"email": 5}], [{"name": "a"}], ["a@x.invalid"],
])
def test_attendee_mailboxes_drops_a_malformed_entry(entries):
    assert ics_mod.attendee_mailboxes(entries) == []


def test_attendee_mailboxes_keeps_a_clean_address_and_strips_mailto():
    assert ics_mod.attendee_mailboxes([{"email": "A@X.invalid"}, {"email": "MAILTO:b@x.invalid"}]) == [
        "A@X.invalid", "b@x.invalid",
    ]


@pytest.mark.parametrize("addr", _HOSTILE_ADDRESSES + ["MAILTO:a@x.invalid"])
def test_native_attendees_safe_refuses_a_hostile_address_in_either_shape(addr):
    assert not ics_mod.native_attendees_safe([{"email": addr}])
    assert not ics_mod.native_attendees_safe([{"emailAddress": {"address": addr}}])


def test_native_attendees_safe_checks_every_address_key_an_entry_carries():
    mixed = {"email": "a@x.invalid", "emailAddress": {"address": "b@x.invalid\r"}}
    assert not ics_mod.native_attendees_safe([mixed])


@pytest.mark.parametrize("entries", [
    None, "a@x.invalid", [{}], [{"emailAddress": {}}], [{"emailAddress": "a@x.invalid"}], [5],
])
def test_native_attendees_safe_refuses_a_malformed_value(entries):
    assert not ics_mod.native_attendees_safe(entries)


@pytest.mark.parametrize("entries", [
    [], [{"email": "a@x.invalid", "responseStatus": "accepted"}],
    [{"emailAddress": {"address": "a@x.invalid", "name": "A"}, "type": "required"}],
])
def test_native_attendees_safe_accepts_provider_shaped_clean_lists(entries):
    assert ics_mod.native_attendees_safe(entries)


def _event_with(attendees):
    from email_triage.engine.models import CalendarEvent
    return CalendarEvent(
        event_id="", summary="s", start=datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc),
        end=datetime(2026, 11, 5, 11, 0, tzinfo=timezone.utc), attendees=attendees,
    )


def test_gmail_serialize_sends_only_safe_mailboxes():
    from email_triage.providers.gmail_calendar import GoogleCalendarProvider
    p = GoogleCalendarProvider(account="x", client_id="", client_secret="", refresh_token="")
    body = p._serialize(_event_with([{"email": "a@x.invalid, b@x.invalid"}, {"email": "ok@x.invalid"}]))
    assert body["attendees"] == [{"email": "ok@x.invalid"}]


def test_office365_serialize_sends_only_safe_mailboxes():
    from email_triage.providers.office365_calendar import Office365CalendarProvider
    event = _event_with([{"email": "a@x.invalid\r\nb"}, {"email": "ok@x.invalid"}])
    body = Office365CalendarProvider._serialize(object(), event)
    assert body["attendees"] == [{"emailAddress": {"address": "ok@x.invalid"}, "type": "required"}]


def test_both_providers_refuse_an_unsafe_attendee_in_a_partial_update():
    import asyncio
    from email_triage.providers.gmail_calendar import GoogleCalendarProvider
    from email_triage.providers.office365_calendar import Office365CalendarProvider
    bad = {"attendees": [{"email": "a@x.invalid, b@x.invalid"}]}
    g = GoogleCalendarProvider(account="x", client_id="", client_secret="", refresh_token="")
    with pytest.raises(ValueError):
        asyncio.run(g.update_event("e1", bad))
    with pytest.raises(ValueError):
        asyncio.run(Office365CalendarProvider.update_event(object(), "e1", bad))
