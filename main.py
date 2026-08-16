"""Standalone GCP Cloud Function (1st gen) entry point - kept so this
repo still builds, runs, and deploys on its own. The primary deploy
path is via dash-xd/pyspace-minimal's router action, which imports
gcp_python_function_inspector.router.register instead (see
xd-dash/huram-abi's deploy-runtime-introspection workflow).
"""
import json

from flask import Request

from gcp_python_function_inspector.introspect import introspect


def main(request: Request):
    if request.method != "GET":
        return (
            json.dumps({"error": "GET only", "method": request.method}, indent=2),
            405,
            {"Content-Type": "application/json"},
        )
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
