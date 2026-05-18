"""Exception-to-string formatting helper.

``str(exc)`` returns the empty string for some bare exceptions
(``ValueError()`` with no args, ``sqlite3.IntegrityError`` before
``.args`` is populated, third-party libs that raise blank exceptions
in error paths). Logging that produces ``error=`` (empty value) tells
the operator nothing actionable.

``fmt_exc(e)`` returns ``str(e)`` when non-empty, otherwise ``repr(e)``
which always carries the exception class + any args. Use this anywhere
an exception is rendered for an operator-facing log line, error dict,
or audit detail.
"""

from __future__ import annotations


def fmt_exc(e: BaseException) -> str:
    """Render an exception so the operator always sees something.

    Returns ``str(e)`` when non-empty; otherwise falls back to
    ``repr(e)`` (which always includes the exception class name).

    Examples:
        >>> fmt_exc(ValueError("bad input"))
        'bad input'
        >>> fmt_exc(ValueError())     # str() would be ""
        'ValueError()'
        >>> fmt_exc(OSError(2, "no such file"))
        '[Errno 2] no such file'
    """
    return str(e) or repr(e)
