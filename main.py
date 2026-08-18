"""Standalone GCP Cloud Function (1st gen) entry point, built on
dash-xd/pyspace-minimal's CloudFunctionApp - the same generic host
xd-dash/huram-abi's deploy-runtime-introspection workflow deploys this
router through (see gcp_python_function_inspector/router.py), just
with ROUTER_MODULE defaulted to this repo's own router instead of
relying on that being set externally, so this repo still builds, runs,
and deploys standalone.
"""
import os
from os import path

os.environ.setdefault("ROUTER_MODULE", "gcp_python_function_inspector.router")

from cloud_function_app import CloudFunctionApp

main = CloudFunctionApp(root=path.dirname(path.abspath(__file__))).build()
