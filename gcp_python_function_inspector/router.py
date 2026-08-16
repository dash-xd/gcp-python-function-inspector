"""Route-providing module: exposes register(app) so a generic Flask
host (see dash-xd/pyspace-minimal) can serve this function's routes
without importing this repo's own deploy machinery directly.

Deliberately not registered at "/": a generic host built on
functions-framework (see pyspace-minimal/main.py) binds its own
catch-all "/" rule to a fallback function it requires as its target,
and Werkzeug's route matching for two rules bound to the identical
literal path "/" is ambiguous/insertion-order-dependent rather than
cleanly overridable - a distinct literal path avoids that entirely by
always outranking the host's separate "/<path:path>" catch-all rule.
"""
import json

from gcp_python_function_inspector.introspect import introspect


def register(app):
    """Registers this repo's routes onto app."""

    @app.route("/runtime-introspection", methods=["GET"])
    def runtime_introspection():
        try:
            result = introspect()
            return (
                json.dumps(result, indent=2, sort_keys=True, default=str),
                200,
                {"Content-Type": "application/json"},
            )
        except Exception as exc:
            return (
                json.dumps({"error": type(exc).__name__, "message": str(exc)}, indent=2),
                500,
                {"Content-Type": "application/json"},
            )
