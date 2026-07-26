"""Pin: every ``match_topics_for_message(...)`` call threads ``categories=``.

The topic-match seam re-classifies each message; the production classifier
carries no ``.categories``, so a call that omits ``categories=`` resolves the
taxonomy to ``{}``. Before the §4.4 decouple that silently dropped EVERY verdict
— and it was the proximate cause of "Preview matches does nothing": the preview
call site omitted ``categories=`` while the back-scan + live-triage sites passed
it (only 1 of 3 sites was wrong — exactly the drift a count-agnostic pin
catches). The decouple now keeps verdicts regardless, but threading the owner's
taxonomy stays the correct, non-drifting convention (it yields a real
in-taxonomy core category), so pin it interprocedurally: a NEW call site can't
silently omit it.
"""

from __future__ import annotations

import ast

from _pin_harness import walk_src

_FN = "match_topics_for_message"


def _call_name(node: ast.Call) -> str | None:
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


def _calls_missing_categories_in_tree(tree: ast.AST) -> list[int]:
    out: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) == _FN:
            kwargs = {k.arg for k in node.keywords if k.arg}
            if "categories" not in kwargs:
                out.append(node.lineno)
    return out


def test_every_match_topics_call_threads_categories():
    offenders: list[str] = []
    for _path, rel, tree in walk_src():
        for lineno in _calls_missing_categories_in_tree(tree):
            offenders.append(f"src/email_triage/{rel}:{lineno}")
    assert not offenders, (
        f"{_FN}(...) call(s) omit categories= — the taxonomy resolves to {{}} "
        "(the prod classifier has no .categories). Thread the owner's taxonomy "
        "like jobs/topic_backscan.py / web/triage_one.py do "
        "(get_categories_dict(..., user_id=owner)):\n  " + "\n  ".join(offenders)
    )


def test_pin_has_teeth():
    """The detector must FLAG a call that omits categories= and PASS one that
    includes it (anti-vacuous, PD#16)."""
    bad = ast.parse(
        "match_topics_for_message(msg, topics, clf, body_keywords=k)\n"
    )
    good = ast.parse(
        "match_topics_for_message(msg, topics, clf, body_keywords=k, "
        "categories=cats)\n"
    )
    assert _calls_missing_categories_in_tree(bad) == [1]
    assert _calls_missing_categories_in_tree(good) == []
