"""N-556 / punch 553 — structural pins for the update-check SSOTs.

Count-agnostic properties over EVERY source file (``_pin_harness.iter_src_files``)
and EVERY template (``iter_template_files``); no site lists, no ``len(X)==N``.
Each detector ships a teeth test that plants the bad shape (and, where an
exemption exists, a good shape that must NOT be flagged).

The SSOTs pinned here (all in ``src/email_triage/update_check.py`` unless noted):

A. **Off-switch parse.** The raw ``release_check_url`` value (YAML key or form
   field) and the update-check form controls are read ONLY in
   ``update_check.py``. The pre-553 defect was a second reader in ``config.py``
   doing ``a.get(key, default) or default`` — a blank fell back to GitHub.
B. **Default address literal.** The GitHub ``/releases`` URL for this repo is
   spelled once (``DEFAULT_RELEASE_CHECK_URL``) — no restated literal in code or
   templates (R7b). Punch 584: matched without regard to case and for BOTH
   repository names (the private development repo the default named until
   584, and the public mirror it names now), since GitHub treats either
   spelling as the same address.
A2. **The address is written only by the SSOT** (punch 584). No code outside
   ``update_check.py`` builds a mapping or subscript-assigns an off-switch key;
   the config Save routes through ``release_check_yaml_fields``. The pre-584
   defect was ``_write_config_yaml`` writing the in-force default into the
   YAML, which froze it there.
C. **Release-marker parser.** The ``email-triage-release-meta`` marker token is
   parsed in one module only — a second parser could disagree about what counts
   as "not a security release".
D. **Per-user dismissal store** (``web/db.py``). Settings keys of the form
   ``user:{id}:<...dismiss...>`` and the namespace literals are built only
   there.
E. **Security banner is not dismissable.** No template that renders
   ``update_check_banners.security`` carries a dismiss control.
H. **The chained records survive HIPAA redaction** (hipaa-b1 O5-H2/H4). Every
   logger call in src whose message is one of the feature's record messages
   (``DISCLOSURE_ACK_LOG_MSG`` / ``UPDATE_CHECK_CHANGED_LOG_MSG``, by constant
   name or literal value) passes ONLY keys that ``redact_persisted_extra``
   keeps in HIPAA mode: derived from the call sites, not a key list.
G. **Every release fetch sits behind the off-switch.** Every function that
   calls ``fetch_latest_release`` also reads ``release_check_url`` (the
   resolved, possibly-blank value) — a new caller fetching a hard-coded URL
   would bypass the switch.

SCOPE CAVEAT (what a green run does NOT prove): (A) sees string-constant keys
only — a key built at runtime (``"release_" + "check_url"``) or smuggled
through ``**kwargs`` is invisible; (B)/(C) see literals and f-string constant
parts, not values assembled from variables; (E) reads template TEXT, so a
dismiss control injected by JavaScript is invisible; (G) proves the function
REFERENCES the setting, not that it guards on it — the behavioural tests in
``tests/test_update_check_553.py`` and ``tests/test_web/test_update_check_553_web.py``
prove the guard.
"""

from __future__ import annotations

import ast
import re

import pytest

from _pin_harness import (
    assert_pin_has_teeth,
    docstring_constant_ids,
    iter_src_files,
    iter_template_files,
    parse_module,
    relpath,
    TEMPLATES_ROOT,
)

_SSOT = "update_check.py"
_DISMISSAL_SSOT = "web/db.py"

_OFFSWITCH_KEYS = frozenset({
    "release_check_url",
    "admin_email_release_check_url",
    "update_check_enabled",
    "__update_check_fields_present",
})
_DEFAULT_URL_NEEDLES = (
    "api.github.com/repos/c-laforest/email-triage/releases",
    "api.github.com/repos/unlimited-data-works-llc/email-triage/releases",
)
_MARKER_NEEDLE = "email-triage-release-meta"
_DISMISS_NAMESPACES = frozenset({
    "dashboard_dismissed_steps", "egress_disclosures_dismissed",
})


#: The SSOT's names for those keys. A read keyed on the imported constant
#: (``a.get(RELEASE_CHECK_URL_KEY)``) is the same read as the literal one.
_OFFSWITCH_KEY_NAMES = frozenset({
    "RELEASE_CHECK_URL_KEY", "FORM_URL_FIELD", "FORM_ENABLED_FIELD",
    "FORM_SECTION_MARKER",
})


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_offswitch_key(node: ast.AST) -> bool:
    if _const_str(node) in _OFFSWITCH_KEYS:
        return True
    if isinstance(node, ast.Name) and node.id in _OFFSWITCH_KEY_NAMES:
        return True
    return isinstance(node, ast.Attribute) and node.attr in _OFFSWITCH_KEY_NAMES


# --- A. off-switch raw reads ------------------------------------------------

def _offswitch_raw_reads(tree: ast.AST) -> list[int]:
    hits: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("get", "pop", "setdefault", "getlist")
            and node.args
            and _is_offswitch_key(node.args[0])
        ):
            hits.append(node.lineno)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Load)
            and _is_offswitch_key(node.slice)
        ):
            hits.append(node.lineno)
        elif (
            isinstance(node, ast.Compare)
            and _is_offswitch_key(node.left)
            and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
        ):
            hits.append(node.lineno)
    return hits


def test_offswitch_value_is_read_only_in_the_ssot():
    offenders = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for line in _offswitch_raw_reads(tree):
            offenders.append(f"{rel}:{line}")
    assert not offenders, (
        "update-check setting read outside update_check.py (route it through "
        "parse_release_check_url / resolve_release_check_form): "
        + ", ".join(offenders)
    )


def test_offswitch_pin_has_teeth():
    assert_pin_has_teeth(
        _offswitch_raw_reads,
        bad_source=(
            "def load(a, d):\n"
            "    return a.get('release_check_url', d) or d\n"
        ),
        good_source=(
            "def write(cfg):\n"
            "    return {'release_check_url': cfg.admin_email.release_check_url}\n"
        ),
    )
    assert_pin_has_teeth(
        _offswitch_raw_reads,
        bad_source="def f(form):\n    return 'update_check_enabled' in form\n",
    )
    assert_pin_has_teeth(
        _offswitch_raw_reads,
        bad_source="def f(raw):\n    return raw['release_check_url']\n",
    )


def test_ssot_actually_holds_the_reads():
    """Invariant A is not vacuous: the SSOT itself does read the setting."""
    from _pin_harness import SRC_ROOT
    tree = parse_module(SRC_ROOT / _SSOT)
    assert tree is not None and _offswitch_raw_reads(tree), (
        "update_check.py no longer reads the setting — the pin above would be "
        "green over nothing"
    )


# --- B. default URL literal ---------------------------------------------------

def _code_strings(tree: ast.AST):
    """(lineno, text) for every code (non-docstring) string constant and
    f-string literal part."""
    skip = docstring_constant_ids(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in skip:
                yield node.lineno, node.value
        elif isinstance(node, ast.JoinedStr):
            text = "".join(
                v.value for v in node.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            yield node.lineno, text


def _literal_sites(needle: str):
    def detector(tree: ast.AST) -> list[int]:
        return [ln for ln, s in _code_strings(tree) if needle in s]
    return detector


def _any_literal_sites(needles, *, fold_case: bool = False):
    """``_literal_sites`` for several needles; ``fold_case`` matches without
    regard to case (the needles must then be lower-case)."""
    def detector(tree: ast.AST) -> list[int]:
        return [
            ln for ln, s in _code_strings(tree)
            if any(n in (s.lower() if fold_case else s) for n in needles)
        ]
    return detector


def test_default_release_url_is_spelled_once():
    detector = _any_literal_sites(_DEFAULT_URL_NEEDLES, fold_case=True)
    offenders = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        offenders += [f"{rel}:{ln}" for ln in detector(tree)]
    for path in iter_template_files():
        text = path.read_text(encoding="utf-8").lower()
        if any(n in text for n in _DEFAULT_URL_NEEDLES):
            offenders.append(relpath(path, TEMPLATES_ROOT))
    assert not offenders, (
        "the default update-check URL is restated outside "
        "update_check.DEFAULT_RELEASE_CHECK_URL: " + ", ".join(offenders)
    )


def test_default_release_url_pin_has_teeth():
    detector = _any_literal_sites(_DEFAULT_URL_NEEDLES, fold_case=True)
    assert_pin_has_teeth(
        detector,
        bad_source=(
            "URL = 'https://api.github.com/repos/c-laforest/email-triage/"
            "releases/latest'\n"
        ),
        good_source=(
            "def f():\n"
            "    '''Mentions api.github.com/repos/c-laforest/email-triage/"
            "releases in prose only.'''\n"
            "    return 1\n"
        ),
    )
    # Punch 584: the public-mirror spelling, in any case, is the same address.
    assert_pin_has_teeth(
        detector,
        bad_source=(
            "URL = 'https://api.github.com/repos/Unlimited-Data-Works-LLC/"
            "Email-Triage/releases/latest'\n"
        ),
    )


# --- A2. off-switch writes ----------------------------------------------------

def _offswitch_raw_writes(tree: ast.AST) -> list[int]:
    """Mapping keys and subscript stores of an off-switch key. A keyword
    argument is NOT matched: ``AdminEmailConfig(release_check_url=...)`` sets
    the in-memory field of the same name, not a YAML entry. SCOPE CAVEAT (what
    a green run does not prove): ``dict(release_check_url=...)``,
    ``d.update(release_check_url=...)``, ``d.setdefault(KEY, v)``, a helper
    ``put(d, k, v)`` called with the key, and an ``asdict(config)`` dump are
    all invisible. Today the one YAML writer is ``_write_config_yaml``."""
    hits: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            hits += [k.lineno for k in node.keys
                     if k is not None and _is_offswitch_key(k)]
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and _is_offswitch_key(node.slice)
        ):
            hits.append(node.lineno)
    return hits


def test_offswitch_value_is_written_only_in_the_ssot():
    offenders = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        offenders += [f"{rel}:{ln}" for ln in _offswitch_raw_writes(tree)]
    assert not offenders, (
        "update-check setting written outside update_check.py (route the "
        "write through release_check_yaml_fields): " + ", ".join(offenders)
    )


def test_offswitch_write_pin_has_teeth():
    assert_pin_has_teeth(
        _offswitch_raw_writes,
        bad_source=(
            "def write(cfg):\n"
            "    return {'release_check_url': cfg.admin_email.release_check_url}\n"
        ),
        good_source=(
            "def write(cfg):\n"
            "    return {'recipients': [], **release_check_yaml_fields(\n"
            "        cfg.admin_email.release_check_url)}\n"
        ),
    )
    assert_pin_has_teeth(
        _offswitch_raw_writes,
        bad_source="def f(d, u):\n    d['release_check_url'] = u\n",
    )
    assert_pin_has_teeth(
        _offswitch_raw_writes,
        bad_source="def f(d, u):\n    d[RELEASE_CHECK_URL_KEY] = u\n",
    )


def test_ssot_actually_holds_the_write_rule():
    """Invariant A2 is not vacuous: the SSOT itself writes the key."""
    from _pin_harness import SRC_ROOT
    tree = parse_module(SRC_ROOT / _SSOT)
    assert tree is not None and _offswitch_raw_writes(tree), (
        "update_check.py no longer builds the address entry — the write pin "
        "would be green over nothing"
    )


# --- C. one marker parser -----------------------------------------------------

def test_release_marker_parsed_in_one_module():
    detector = _literal_sites(_MARKER_NEEDLE)
    offenders = []
    holder_hits = 0
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        hits = detector(tree)
        if rel == _SSOT:
            holder_hits = len(hits)
            continue
        offenders += [f"{rel}:{ln}" for ln in hits]
    assert not offenders, (
        "a second release-marker parser exists: " + ", ".join(offenders)
    )
    assert holder_hits, "update_check.py no longer carries the marker token"


def test_release_marker_pin_has_teeth():
    assert_pin_has_teeth(
        _literal_sites(_MARKER_NEEDLE),
        bad_source="import re\nR = re.compile(r'email-triage-release-meta:(.*)')\n",
    )


# --- D. one per-user dismissal store -------------------------------------------

def _dismissal_key_sites(tree: ast.AST) -> list[int]:
    hits: list[int] = []
    for ln, s in _code_strings(tree):
        if s in _DISMISS_NAMESPACES:
            hits.append(ln)
        elif s.startswith("user:") and "dismiss" in s:
            hits.append(ln)
    return hits


def test_dismissal_keys_built_only_in_the_store():
    offenders = []
    holder = False
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        hits = _dismissal_key_sites(tree)
        if rel == _DISMISSAL_SSOT:
            holder = bool(hits)
            continue
        offenders += [f"{rel}:{ln}" for ln in hits]
    assert not offenders, (
        "per-user dismissal key built outside web/db.py (use "
        "get_user_dismissals / add_user_dismissal): " + ", ".join(offenders)
    )
    assert holder, "web/db.py no longer declares the dismissal namespaces"


def test_dismissal_key_pin_has_teeth():
    assert_pin_has_teeth(
        _dismissal_key_sites,
        bad_source=(
            "def k(uid):\n"
            "    return f'user:{uid}:egress_disclosures_dismissed'\n"
        ),
        good_source="def k(uid):\n    return f'user:{uid}:digest_prefs'\n",
    )


# --- E. the security banner has no dismiss control -----------------------------

_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.DOTALL)
_DISMISS_CONTROL = re.compile(r"hx-post|dismiss|<form\b|<button\b", re.IGNORECASE)


#: The non-dismissable update-check notices (the security banner and the
#: check-failing banner, db F-O5-1).
_NON_DISMISSABLE_CTX = ("update_check_banners.security", "update_check_banners.stale")


def _security_banner_has_dismiss(text: str) -> bool:
    code = _JINJA_COMMENT.sub("", text)
    if not any(ctx in code for ctx in _NON_DISMISSABLE_CTX):
        return False
    return bool(_DISMISS_CONTROL.search(code))


def test_security_banner_templates_carry_no_dismiss_control():
    renderers = []
    offenders = []
    for path in iter_template_files():
        text = path.read_text(encoding="utf-8")
        code = _JINJA_COMMENT.sub("", text)
        if any(ctx in code for ctx in _NON_DISMISSABLE_CTX):
            renderers.append(relpath(path, TEMPLATES_ROOT))
        if _security_banner_has_dismiss(text):
            offenders.append(relpath(path, TEMPLATES_ROOT))
    assert len({c for c in _NON_DISMISSABLE_CTX
                for r in renderers
                if c in _JINJA_COMMENT.sub("", (TEMPLATES_ROOT / r).read_text(encoding="utf-8"))}
               ) == len(_NON_DISMISSABLE_CTX), (
        "a non-dismissable notice has no rendering template (pin vacuous)"
    )
    assert not offenders, (
        "the security-update banner must not be dismissable: " + ", ".join(offenders)
    )


def test_security_banner_pin_has_teeth():
    bad = (
        "{% if update_check_banners.security %}<aside>x"
        "<button hx-post=\"/admin/disclosures/dismiss\">hide</button></aside>"
        "{% endif %}"
    )
    good = (
        "{# no dismiss button here #}"
        "{% if update_check_banners.security %}<aside>x</aside>{% endif %}"
    )
    assert _security_banner_has_dismiss(bad)
    assert not _security_banner_has_dismiss(good)
    assert _security_banner_has_dismiss(
        "{% if update_check_banners.stale %}<form hx-post=\"/x\"></form>{% endif %}"
    )


# --- G. every fetch is behind the off-switch -----------------------------------

def _unguarded_fetch_sites(tree: ast.AST) -> list[int]:
    hits: list[int] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls_fetch = False
        reads_switch = False
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                callee = node.func
                name = (
                    callee.id if isinstance(callee, ast.Name)
                    else callee.attr if isinstance(callee, ast.Attribute)
                    else None
                )
                if name == "fetch_latest_release":
                    calls_fetch = True
                # asyncio.to_thread(fetch_latest_release, url) — the callee
                # passed by reference is still a fetch.
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == "fetch_latest_release":
                        calls_fetch = True
            if isinstance(node, ast.Attribute) and node.attr == "release_check_url":
                reads_switch = True
            if _const_str(node) == "release_check_url":
                reads_switch = True
        if calls_fetch and not reads_switch:
            hits.append(fn.lineno)
    return hits


def test_every_release_fetch_reads_the_off_switch():
    callers = 0
    offenders = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        src = path.read_text(encoding="utf-8")
        if "fetch_latest_release" in src:
            callers += 1
        offenders += [f"{relpath(path)}:{ln}" for ln in _unguarded_fetch_sites(tree)]
    assert callers, "no caller of fetch_latest_release found (pin vacuous)"
    assert not offenders, (
        "fetch_latest_release called from a function that never reads "
        "admin_email.release_check_url (bypasses the off-switch): "
        + ", ".join(offenders)
    )


def test_unguarded_fetch_pin_has_teeth():
    assert_pin_has_teeth(
        _unguarded_fetch_sites,
        bad_source=(
            "def f():\n"
            "    return fetch_latest_release('https://example.invalid/r')\n"
        ),
        good_source=(
            "def f(config):\n"
            "    url = config.admin_email.release_check_url\n"
            "    if not url:\n"
            "        return None\n"
            "    return fetch_latest_release(url)\n"
        ),
    )
    assert_pin_has_teeth(
        _unguarded_fetch_sites,
        bad_source=(
            "async def f():\n"
            "    return await asyncio.to_thread(fetch_latest_release, 'u')\n"
        ),
    )


# --- H. the chained records survive HIPAA-mode redaction ------------------------

def _record_msgs() -> dict[str, str]:
    from email_triage import update_check as uc
    return {
        "DISCLOSURE_ACK_LOG_MSG": uc.DISCLOSURE_ACK_LOG_MSG,
        "UPDATE_CHECK_CHANGED_LOG_MSG": uc.UPDATE_CHECK_CHANGED_LOG_MSG,
    }


def _record_call_keys(tree: ast.AST) -> list[tuple[int, str, list[str]]]:
    """(lineno, message-constant, kwarg keys) for each logger call whose first
    arg is one of the record messages (by constant name or literal value)."""
    msgs = _record_msgs()
    by_value = {v: k for k, v in msgs.items()}
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("info", "warning", "error", "critical")
                and node.args):
            continue
        first = node.args[0]
        name = None
        if isinstance(first, ast.Name) and first.id in msgs:
            name = first.id
        elif isinstance(first, ast.Attribute) and first.attr in msgs:
            name = first.attr
        elif _const_str(first) in by_value:
            name = by_value[_const_str(first)]
        if name is None:
            continue
        keys = [kw.arg if kw.arg is not None else "**" for kw in node.keywords]
        out.append((node.lineno, name, keys))
    return out


def _redacted_keys(keys: list[str]) -> list[str]:
    from email_triage.triage_logging import (
        _REDACTED_PLACEHOLDER, redact_persisted_extra,
    )
    bad = []
    for k in keys:
        if k == "**":
            bad.append("**kwargs (keys unknowable)")
            continue
        if redact_persisted_extra({k: "v"}, hipaa=True)[k] == _REDACTED_PLACEHOLDER:
            bad.append(k)
    return bad


def test_feature_records_survive_hipaa_redaction():
    seen: set[str] = set()
    offenders = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        for line, name, keys in _record_call_keys(tree):
            seen.add(name)
            bad = _redacted_keys(keys)
            if bad:
                offenders.append(f"{relpath(path)}:{line} {name}: {bad}")
    assert seen == set(_record_msgs()), (
        "record message(s) with no call site (pin vacuous): "
        f"{set(_record_msgs()) - seen}"
    )
    assert not offenders, (
        "a chained update-check/disclosure record carries a key HIPAA mode "
        "redacts (add it to triage_logging._PERSIST_SAFE_KEYS after confirming "
        "non-PHI, or drop it): " + ", ".join(offenders)
    )


def test_record_survival_pin_has_teeth():
    def detector(tree):
        return [
            k for _ln, _n, keys in _record_call_keys(tree)
            for k in _redacted_keys(keys)
        ]

    assert_pin_has_teeth(
        detector,
        bad_source=(
            "def f(log, url):\n"
            "    log.info(UPDATE_CHECK_CHANGED_LOG_MSG, full_url=url)\n"
        ),
        good_source=(
            "def f(log):\n"
            "    log.info('Egress disclosure acknowledged', "
            "disclosure_id='egress:update_check:h', user_id=1)\n"
        ),
    )
    assert_pin_has_teeth(
        detector,
        bad_source="def f(log, **k):\n    log.info(DISCLOSURE_ACK_LOG_MSG, **k)\n",
    )


# --- I. a release link is admitted only through release_page_url ------------------

#: Release-payload fields that are displayed (banner + plain-text email) and
#: so may be admitted only through the update_check SSOT helpers
#: (``release_page_url`` / ``release_tag``; round 4 added the tag).
_DISPLAYED_PAYLOAD_FIELDS = frozenset({"html_url", "tag_name"})


def _raw_html_url_reads(tree: ast.AST) -> list[int]:
    """Lines that read a displayed payload field other than via the SSOT."""
    hits = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get" and node.args
                and _const_str(node.args[0]) in _DISPLAYED_PAYLOAD_FIELDS):
            hits.append(node.lineno)
        elif (isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load)
              and _const_str(node.slice) in _DISPLAYED_PAYLOAD_FIELDS):
            hits.append(node.lineno)
    return hits


def test_release_link_admitted_only_via_the_ssot():
    """DA O5-F1 / db F-O5-2: ``html_url`` becomes an <a href> (banner + email);
    only ``update_check.release_page_url`` (https-only) may read it."""
    offenders, holder = [], False
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        hits = _raw_html_url_reads(tree)
        if rel == _SSOT:
            holder = bool(hits)
            continue
        offenders += [f"{rel}:{ln}" for ln in hits]
    assert holder, "update_check.py no longer reads html_url (pin vacuous)"
    assert not offenders, (
        "html_url read outside update_check.release_page_url: "
        + ", ".join(offenders)
    )


def test_release_link_pin_has_teeth():
    assert_pin_has_teeth(
        _raw_html_url_reads,
        bad_source="def f(payload):\n    return payload.get('html_url') or None\n",
        good_source="def f(payload):\n    return release_page_url(payload)\n",
    )
    assert_pin_has_teeth(
        _raw_html_url_reads,
        bad_source="def f(payload):\n    return payload['tag_name']\n",
        good_source="def f(payload):\n    return release_tag(payload)[0]\n",
    )


# --- J. the update-check settings rows are written only by the SSOT ---------------

_SETTING_KEY_VALUES = ("update_check:release_facts", "update_check:health")
_SETTING_KEY_NAMES = frozenset({"FACTS_SETTING_KEY", "HEALTH_SETTING_KEY"})


def _settings_key_sites(tree: ast.AST) -> list[int]:
    hits = [ln for ln, s in _code_strings(tree) if s in _SETTING_KEY_VALUES]
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _SETTING_KEY_NAMES:
            hits.append(node.lineno)
        elif isinstance(node, ast.Attribute) and node.attr in _SETTING_KEY_NAMES:
            hits.append(node.lineno)
    return hits


def test_update_check_settings_rows_only_in_the_ssot():
    """db F-O5-1 / PD-18: the facts row and the check-health row (whose set
    and clear edges go through ``record_check_outcome``) are touched only in
    ``update_check.py``."""
    offenders, holder = [], False
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        hits = _settings_key_sites(tree)
        if rel == _SSOT:
            holder = bool(hits)
            continue
        offenders += [f"{rel}:{ln}" for ln in hits]
    assert holder, "update_check.py no longer declares the settings keys"
    assert not offenders, (
        "update-check settings row touched outside update_check.py: "
        + ", ".join(offenders)
    )


def test_settings_row_pin_has_teeth():
    assert_pin_has_teeth(
        _settings_key_sites,
        bad_source=(
            "def f(db):\n"
            "    set_setting(db, 'update_check:health', {'consecutive_failures': 0})\n"
        ),
        good_source="def f(db):\n    record_check_outcome(db, 'ok', now_iso='x')\n",
    )


# --- K. the global banner slot adds no form controls to every page --------------
#
# 553 landing (E2E failure on 02af36ff) + panel B1 R5 (DA R5-F1, R5-F2).
#
# SCOPE CAVEAT (what a green run does NOT prove):
# - Templates reached through a VARIABLE include (``{% include x %}``) cannot
#   be resolved statically; the walk refuses them (counted as an offender) rather
#   than skipping them, so a green run means there are none in the slot.
# - Markup produced by a MACRO call (``{{ m.button(...) }}``) or a filter is
#   not expanded; only literal tags in the slot's templates are read.
# - Controls injected by JavaScript at runtime are invisible here; the e2e
#   help-page test (``tests/e2e/test_help_me.py``) and the rendered-view test
#   ``test_disclosure_banner_adds_no_page_controls`` cover the rendered page.

_INCLUDE_RE = re.compile(r"""\{%-?\s*include\s+(.+?)\s*-?%\}""", re.DOTALL)
_STRING_INCLUDE_RE = re.compile(r"""^["']([^"']+)["']""")
_CONTROL_TAG_RE = re.compile(r"<(button|input)\b([^>]*)>", re.IGNORECASE | re.DOTALL)
_ATTR_TYPE_RE = re.compile(
    r"""(?<![\w-])type\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE,
)
_QUOTED_VALUE_RE = re.compile(r"""=\s*(?:"[^"]*"|'[^']*')""")


def _global_slot_controls(text: str) -> list[str]:
    """Every page-colliding control in a partial's markup (Jinja comments
    stripped). Each finding names its shape:

    - ``<form>``; ``hx-vals``; a ``formaction`` or ``form=`` attribute on
      any element (it submits, or joins, a page's form);
    - a ``<button>`` that is not provably ``type="button"``: untyped (the
      HTML default is submit), ``submit``/``reset``, or a templated type;
    - an ``<input>`` of type ``submit``/``image``/``reset`` or a templated
      type;
    - a ``<button>``/``<input>`` with a templated attribute set outside a
      quoted value (``{{ attrs }}`` could inject any of the above).
    """
    code = _JINJA_COMMENT.sub("", text)
    hits: list[str] = []
    if re.search(r"<form\b", code, re.IGNORECASE):
        hits.append("<form>")
    if re.search(r"(?<![\w-])hx-vals\s*=", code, re.IGNORECASE):
        hits.append("hx-vals")
    if re.search(r"(?<![\w-])formaction\s*=", code, re.IGNORECASE):
        hits.append("formaction=")
    for m in _CONTROL_TAG_RE.finditer(code):
        tag, attrs = m.group(1).lower(), m.group(2)
        bare = _QUOTED_VALUE_RE.sub("=", attrs)
        if re.search(r"(?<![\w-])form\s*=", bare, re.IGNORECASE):
            hits.append(f"<{tag} form=>")
        if "{{" in bare or "{%" in bare:
            hits.append(f"<{tag}> templated attributes")
        t = _ATTR_TYPE_RE.search(attrs)
        value = None if t is None else next(g for g in t.groups() if g is not None)
        if value is not None and ("{{" in value or "{%" in value):
            hits.append(f"<{tag} type> templated")
            continue
        if tag == "button":
            if value is None:
                hits.append("<button> untyped (default submit)")
            elif value.strip().lower() != "button":
                hits.append(f"<button type={value.strip().lower()}>")
        elif value is not None and value.strip().lower() in ("submit", "image", "reset"):
            hits.append(f"<input type={value.strip().lower()}>")
    return hits


def _global_slot_templates() -> tuple[list[str], list[str]]:
    """Every template reachable from base.html through includes (followed
    recursively, R5-F2), and every include that cannot be resolved (a
    variable include)."""
    seen: list[str] = []
    unresolved: list[str] = []
    queue = ["base.html"]
    while queue:
        rel = queue.pop(0)
        text = _JINJA_COMMENT.sub(
            "", (TEMPLATES_ROOT / rel).read_text(encoding="utf-8"),
        )
        for expr in _INCLUDE_RE.findall(text):
            m = _STRING_INCLUDE_RE.match(expr.strip())
            if m is None:
                unresolved.append(f"{rel}: include {expr.strip()}")
                continue
            child = m.group(1)
            if child not in seen:
                seen.append(child)
                queue.append(child)
    return seen, unresolved


def test_base_included_partials_add_no_page_controls():
    """A partial included from base.html (directly or through nested
    includes) renders on EVERY page, so any form control in it collides with
    each page's own selectors (the help page's ``button[type="submit"]``
    resolved to 2 elements). Derived from base.html's include graph, not a
    list."""
    included, unresolved = _global_slot_templates()
    assert included, "base.html includes nothing (pin vacuous)"
    assert not unresolved, (
        "variable include in the global slot (cannot be checked; use a "
        f"string include): {unresolved}"
    )
    offenders = {}
    for rel in included:
        hits = _global_slot_controls(
            (TEMPLATES_ROOT / rel).read_text(encoding="utf-8"),
        )
        if hits:
            offenders[rel] = hits
    assert not offenders, (
        "a base.html-included partial adds page-colliding controls: "
        f"{offenders}"
    )


@pytest.mark.parametrize("bad, shape", [
    ('<form hx-post="/x"><button type="button">x</button></form>', "<form>"),
    ("<button type=submit>x</button>", "<button type=submit>"),
    ('<button type="submit">x</button>', "<button type=submit>"),
    ("<button>x</button>", "<button> untyped (default submit)"),
    ('<button class="a" hx-post="/x">x</button>', "<button> untyped (default submit)"),
    ('<button type="reset">x</button>', "<button type=reset>"),
    ('<button type="button" form="page-form">x</button>', "<button form=>"),
    ('<input type="image" src="/x.png">', "<input type=image>"),
    ("<input type=submit value=go>", "<input type=submit>"),
    ('<button type="{{ kind }}">x</button>', "<button type> templated"),
    ('<input type="{{ t }}">', "<input type> templated"),
    ('<button type="button" formaction="/x">x</button>', "formaction="),
    ('<button type="button" {{ extra_attrs }}>x</button>', "<button> templated attributes"),
    ("<button type=\"button\" hx-vals='{\"a\": 1}'>x</button>", "hx-vals"),
])
def test_global_slot_pin_has_teeth(bad, shape):
    """R5-F1: one planted partial per shape -> the detector names it."""
    assert shape in _global_slot_controls(bad), (shape, _global_slot_controls(bad))


@pytest.mark.parametrize("good", [
    '{# a <form> and <button> in a comment are fine #}'
    '<button type="button" name="disclosure_id" value="{{ d.id }}" '
    'hx-post="/admin/disclosures/dismiss">x</button>',
    '<input type="hidden" name="x" value="{{ v }}">',
    "<button type='button'>x</button>",
    "<a href=\"/x\">a link</a>",
])
def test_global_slot_pin_admits_good_shapes(good):
    assert _global_slot_controls(good) == []


def test_global_slot_walk_follows_nested_includes(tmp_path, monkeypatch):
    """R5-F2: a control two includes deep is found; a variable include is
    refused, not skipped."""
    import _pin_harness as ph
    import test_n556_update_check_ssot_pin as me
    (tmp_path / "admin").mkdir()
    (tmp_path / "base.html").write_text(
        '{% include "admin/outer.html" %}', encoding="utf-8")
    (tmp_path / "admin" / "outer.html").write_text(
        '{% include "admin/inner.html" %}{% include partial_name %}',
        encoding="utf-8")
    (tmp_path / "admin" / "inner.html").write_text(
        "<button>x</button>", encoding="utf-8")
    monkeypatch.setattr(me, "TEMPLATES_ROOT", tmp_path)
    included, unresolved = me._global_slot_templates()
    assert included == ["admin/outer.html", "admin/inner.html"]
    assert unresolved == ["admin/outer.html: include partial_name"]
    assert me._global_slot_controls(
        (tmp_path / "admin" / "inner.html").read_text(encoding="utf-8"),
    ) == ["<button> untyped (default submit)"]
    assert ph.TEMPLATES_ROOT != tmp_path  # the harness constant is untouched
