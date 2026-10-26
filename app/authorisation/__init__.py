"""The authorisation gate.

Nothing in this package talks to the network, and nothing in it imports FastAPI
or anything HTTP-shaped. It is the one piece of logic that stands between a
request to scan and a packet leaving the building, so it is kept small, pure,
and callable from anywhere.
"""

from app.authorisation.gate import AuthorisationDecision, check_authorisation

__all__ = ["AuthorisationDecision", "check_authorisation"]
