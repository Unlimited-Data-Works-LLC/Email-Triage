"""Punch 443: the form-limit facts in ``web/form_limits.py`` are MEASURED, every run.

The module docstring used to carry a 1.3.1 reading ("urlencoded field count is
NOT enforced") that the installed library contradicts. A docstring is not a
measurement, so this pin builds a tiny Starlette app and posts the shapes the
docstring describes, against whatever Starlette/python-multipart the lock
installed. A library bump that moves a limit turns this red instead of leaving
the prose stale.
"""
from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from email_triage.web.form_limits import (
    FORM_DEFAULT_MAX_PART_SIZE,
    FORM_FOLDER_PATH_MAX_PART_SIZE,
    FORM_MAX_FIELDS,
    FORM_MAX_PART_SIZE,
    parse_form,
)

MIB = 1024 * 1024


async def _default(request: Request):
    try:
        form = await request.form()
    except Exception as e:  # HTTPException(400) from the form parser
        return JSONResponse({"err": str(e)}, status_code=getattr(e, "status_code", 500))
    return JSONResponse({"n": len(form.multi_items())})


async def _raised(request: Request):
    try:
        form = await parse_form(request)
    except Exception as e:
        return JSONResponse({"err": str(e)}, status_code=getattr(e, "status_code", 500))
    return JSONResponse({"n": len(form.multi_items())})


async def _fields_only(request: Request):
    try:
        form = await parse_form(request, max_part_size=FORM_DEFAULT_MAX_PART_SIZE)
    except Exception as e:
        return JSONResponse({"err": str(e)}, status_code=getattr(e, "status_code", 500))
    return JSONResponse({"n": len(form.multi_items())})


async def _folder_paths(request: Request):
    try:
        form = await parse_form(request, max_part_size=FORM_FOLDER_PATH_MAX_PART_SIZE)
    except Exception as e:
        return JSONResponse({"err": str(e)}, status_code=getattr(e, "status_code", 500))
    return JSONResponse({"n": len(form.multi_items())})


@pytest.fixture(scope="module")
def client():
    app = Starlette(routes=[
        Route("/default", _default, methods=["POST"]),
        Route("/raised", _raised, methods=["POST"]),
        Route("/fields-only", _fields_only, methods=["POST"]),
        Route("/folder-paths", _folder_paths, methods=["POST"]),
    ])
    return TestClient(app, raise_server_exceptions=False)


def _many(n: int) -> dict[str, str]:
    return {f"f{i}": "v" for i in range(n)}


def test_defaults_enforce_both_limits_for_urlencoded_forms(client):
    """The docstring's two claims, measured: 1 MiB per field AND 1000 fields,
    BOTH for urlencoded bodies (the old text said the count was not enforced)."""
    assert client.post("/default", data={"raw": "X" * (MIB // 2)}).status_code == 200
    assert client.post("/default", data={"raw": "X" * (2 * MIB)}).status_code == 400
    assert client.post("/default", data=_many(900)).status_code == 200
    r = client.post("/default", data=_many(30_000))
    assert r.status_code == 400, "urlencoded field count is enforced; the old docstring said it was not"
    assert "fields" in r.text.lower()


def test_defaults_enforce_the_part_count_for_multipart(client):
    parts = lambda n: {f"f{i}": (None, "x") for i in range(n)}  # noqa: E731
    assert client.post("/default", files=parts(900)).status_code == 200
    assert client.post("/default", files=parts(1_100)).status_code == 400


def test_parse_form_raises_both_limits_but_stays_bounded(client):
    assert client.post("/raised", data={"raw": "X" * (2 * MIB)}).status_code == 200
    assert client.post("/raised", data=_many(30_000)).status_code == 200
    # still BOUNDED: one byte class of DoS bound is kept on each axis.
    assert client.post("/raised", data={"raw": "X" * (FORM_MAX_PART_SIZE + MIB)}).status_code == 400
    assert client.post("/raised", data=_many(FORM_MAX_FIELDS + 10_000)).status_code == 400


def test_fields_only_raises_the_count_and_keeps_the_per_field_default(client):
    """The folder include/exclude route's shape: many small fields, no big one."""
    assert client.post("/fields-only", data=_many(30_000)).status_code == 200
    assert client.post("/fields-only", data={"raw": "X" * (2 * MIB)}).status_code == 400


def test_folder_path_cap_bounds_each_field_far_below_the_default(client):
    """db-sme S1: the folder-prefs route raises the COUNT but caps each field at
    ``FORM_FOLDER_PATH_MAX_PART_SIZE`` (a folder path), so the worst case is
    FORM_MAX_FIELDS x 8 KiB, not FORM_MAX_FIELDS x 1 MiB."""
    assert FORM_FOLDER_PATH_MAX_PART_SIZE < FORM_DEFAULT_MAX_PART_SIZE
    assert client.post("/folder-paths", data=_many(30_000)).status_code == 200
    assert client.post("/folder-paths", data={"p": "X" * (FORM_FOLDER_PATH_MAX_PART_SIZE // 2)}).status_code == 200
    assert client.post("/folder-paths", data={"p": "X" * (FORM_FOLDER_PATH_MAX_PART_SIZE * 2)}).status_code == 400


# --- punch 443 residual (class P4): max_files, the multipart per-field cap, and
# the installed defaults themselves. The tests above measure fields and the
# per-field size on urlencoded bodies; these close the multipart axes and pin the
# Starlette constants, so a bump that moves a default turns this file red.

def _files(n: int) -> dict:
    return {f"f{i}": (f"n{i}.txt", b"x") for i in range(n)}


def test_starlette_form_defaults_are_the_ones_the_docstring_states():
    """The module docstring says 1000 files, 1000 fields, 1 MiB per field. Read them
    from the INSTALLED Starlette's signature, not from our prose."""
    import inspect

    params = inspect.signature(Request.form).parameters
    assert params["max_files"].default == 1000
    assert params["max_fields"].default == 1000
    assert params["max_part_size"].default == FORM_DEFAULT_MAX_PART_SIZE == MIB


def test_defaults_enforce_max_files_for_multipart(client):
    """``max_files`` is measured with real file parts (a filename), which the
    field-count test above does not send."""
    assert client.post("/default", files=_files(900)).status_code == 200
    assert client.post("/default", files=_files(1_100)).status_code == 400


def test_parse_form_keeps_max_files_bounded(client):
    """``parse_form`` raises fields and part size but leaves the file count at its
    bound: 1100 file parts still 400."""
    assert client.post("/raised", files=_files(900)).status_code == 200
    assert client.post("/raised", files=_files(1_100)).status_code == 400


def test_multipart_field_size_cap_is_per_non_file_part(client):
    """The per-part size cap is measured on MULTIPART as well as urlencoded: a
    2 MiB non-file part 400s at the default and passes ``parse_form``; a file part
    of the same size is not capped by ``max_part_size`` (it spools)."""
    field = {"raw": (None, "X" * (2 * MIB))}
    assert client.post("/default", files=field).status_code == 400
    assert client.post("/raised", files=field).status_code == 200
    assert client.post("/default", files={"up": ("big.bin", b"X" * (2 * MIB))}).status_code == 200
