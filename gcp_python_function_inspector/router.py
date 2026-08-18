"""Route-providing module: exposes ROUTES, a {url_rule: view_func}
dict, so a generic Flask host (see dash-xd/pyspace-minimal's
CloudFunctionApp) can serve this function's routes without importing
this repo's own deploy machinery directly.

Deliberately not registered at "/": CloudFunctionApp's own
DEFAULT_ROUTES claims that path for its health check, and while a
router's ROUTES can override any rule outright (they're merged into
one dict before anything is registered), /runtime-introspection stays
distinct so this router can be hotloaded alongside others without
implicitly overriding their root route too.
"""
import json

from gcp_python_function_inspector.introspect import introspect


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


ROUTES = {
    "/runtime-introspection": runtime_introspection,
}
