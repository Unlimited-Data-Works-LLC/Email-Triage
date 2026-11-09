"""Route test for POST /profile/sign-out-all.

Panel r15 (DA MUST-1, PD#17): the handler called an undefined ``log`` after
the epoch bump, so every sign-out-all returned a 500 while the revoke had
already landed. No test POSTed the route, so every suite stayed quiet. This
drives the real route: it must redirect to /login, bump ``session_epoch``,
and the cookie that made the request must no longer authenticate.
"""
from __future__ import annotations


def _epoch(db, user_id: int) -> int:
    row = db.execute(
        "SELECT session_epoch FROM users WHERE id = ?", (user_id,),
    ).fetchone()
    return int(row["session_epoch"])


def test_sign_out_all_redirects_bumps_epoch_and_rejects_the_old_cookie(
    client, db, regular_user, user_cookies,
):
    before = _epoch(db, regular_user["id"])
    # The cookie authenticates before the revoke.
    ok = client.get("/profile", cookies=user_cookies, follow_redirects=False)
    assert ok.status_code == 200, ok.status_code

    r = client.post(
        "/profile/sign-out-all", cookies=user_cookies, follow_redirects=False,
    )
    assert r.status_code == 303, (r.status_code, r.text[:300])
    assert r.headers["location"] == "/login"
    assert _epoch(db, regular_user["id"]) == before + 1

    # The same cookie is now stale: the user loader refuses it.
    after = client.get("/profile", cookies=user_cookies, follow_redirects=False)
    assert after.status_code != 200, "revoked session still authenticates"
