"""Runtime patch for aioimaplib's recursive parser.

aioimaplib 2.0.1's :meth:`IMAP4ClientProtocol._handle_responses` recurses
once per CRLF-separated line in the inbound data buffer. Python's default
recursion limit (~1000 frames) is hit when fetching messages that have
more than ~1000 wire lines — typical of large multipart bodies (Iperius
backup reports, marketing HTML newsletters, etc.). The resulting
``RecursionError`` corrupts the protocol state, which in turn causes a
follow-up ``Abort: unexpected tagged ... response`` because the pending
command was already cleared from the dict by the time the server's
``OK Fetch completed`` line arrives.

Upstream tracking: https://github.com/bamthomas/aioimaplib/issues/118
(open since 2025-03-30, no fix shipped at time of writing).

This module imports the inner aioimaplib module, defines an iterative
re-implementation of ``_handle_responses`` with identical control flow,
and replaces the class method at import time. It is idempotent — applying
twice is a no-op.

The patch is removable as soon as upstream ships a fix: delete the file,
remove the import in ``providers/imap.py``, bump the aioimaplib pin.
An optional release-watch entry (configured in the operator's own
release-watch tooling, ``release-watchlist.json``) can fire when
commit messages between aioimaplib tags mention any of:
``recursion``, ``RecursionError``, ``_handle_responses``, ``stack``,
``#118``, ``large response``.
"""

from __future__ import annotations

# Marker so re-import is a no-op.
_PATCHED = False


def apply_aioimaplib_patch() -> bool:
    """Install the iterative ``_handle_responses`` on aioimaplib.

    Returns True if the patch was applied (or was already applied),
    False if aioimaplib couldn't be imported (provider not installed
    in this deploy).
    """
    global _PATCHED
    if _PATCHED:
        return True

    try:
        from aioimaplib.aioimaplib import (
            IMAP4ClientProtocol,
            IncompleteRead,
            CRLF,
            literal_data_re,
            Command,
        )
    except ImportError:
        return False

    def _handle_responses_iter(self, data, line_handler, current_cmd=None):
        """Iterative replacement for the recursive upstream version.

        Mechanical port of the original control flow — every recursive
        ``self._handle_responses(tail, ...)`` call becomes a loop
        iteration that updates ``data`` and ``current_cmd``. Behavior is
        identical for valid IMAP responses; only the call-stack shape
        differs (flat instead of one frame per CRLF line).
        """
        while True:
            if not data:
                if self.pending_sync_command is not None:
                    self.pending_sync_command.flush()
                if current_cmd is not None and current_cmd.wait_data():
                    raise IncompleteRead(current_cmd)
                return

            if (
                current_cmd is not None
                and current_cmd.wait_literal_data()
            ):
                data = current_cmd.append_literal_data(data)
                if current_cmd.wait_literal_data():
                    raise IncompleteRead(current_cmd)

            line, separator, tail = data.partition(CRLF)
            if not separator:
                raise IncompleteRead(current_cmd, data)

            cmd = line_handler(line, current_cmd)

            begin_literal = literal_data_re.match(line)
            if begin_literal:
                size = int(begin_literal.group("size"))
                if cmd is None:
                    cmd = Command("NIL", "unused")
                cmd.begin_literal_data(size)
                current_cmd = cmd
                data = tail
            elif cmd is not None and cmd.wait_data():
                current_cmd = cmd
                data = tail
            else:
                current_cmd = None
                data = tail

    # Preserve introspection — the test harness checks identity to
    # confirm the patch is in place after import.
    _handle_responses_iter.__name__ = "_handle_responses_iter"
    _handle_responses_iter.__qualname__ = (
        "IMAP4ClientProtocol._handle_responses_iter"
    )

    IMAP4ClientProtocol._handle_responses = _handle_responses_iter
    _PATCHED = True
    return True


# Apply on import — providers/imap.py imports this module before any
# aioimaplib instance is created in the process.
apply_aioimaplib_patch()
