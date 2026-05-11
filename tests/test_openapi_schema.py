# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Smoke tests for the drf-spectacular OpenAPI schema generation.

We don't boot the full CAPE web app -- that would drag in PIL/lxml/
yara/etc.  Instead we configure a minimal Django + DRF env in-test
and assert drf-spectacular handles the same patterns CAPE uses:

  - @extend_schema decorator on function-based views
  - @api_view decorator
  - PATH parameters via OpenApiParameter
  - Multi-method endpoints

If those work here, they work in apiv2/views.py.
"""

import json

import pytest

# Configure Django before importing DRF/spectacular.
import django
from django.conf import settings as django_settings

if not django_settings.configured:
    django_settings.configure(
        DEBUG=True,
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "rest_framework",
            "drf_spectacular",
        ],
        REST_FRAMEWORK={
            "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
        },
        SPECTACULAR_SETTINGS={
            "TITLE": "Test",
            "VERSION": "0.0.0",
            "SERVE_INCLUDE_SCHEMA": False,
        },
        ROOT_URLCONF=__name__,
        SECRET_KEY="test",
        USE_TZ=True,
    )
    django.setup()

from django.urls import path  # noqa: E402
from drf_spectacular.generators import SchemaGenerator  # noqa: E402
from drf_spectacular.utils import OpenApiParameter, extend_schema  # noqa: E402
from rest_framework.decorators import api_view  # noqa: E402
from rest_framework.response import Response  # noqa: E402


# ---------- minimal app fixture --------------------------------------

@extend_schema(
    tags=["Tasks"],
    summary="Submit a file",
    description="Multipart upload becoming a task.",
)
@api_view(["POST"])
def tasks_create_file(request):
    return Response({"task_id": 1})


@extend_schema(
    tags=["Tasks"],
    summary="List tasks",
    parameters=[
        OpenApiParameter("limit", int, OpenApiParameter.PATH, required=False),
        OpenApiParameter("offset", int, OpenApiParameter.PATH, required=False),
    ],
)
@api_view(["GET"])
def tasks_list(request, offset=None, limit=None):
    return Response([])


@extend_schema(tags=["Tasks"], summary="Get one task")
@api_view(["GET"])
def tasks_view(request, task_id):
    return Response({"id": task_id})


urlpatterns = [
    path("apiv2/tasks/create/file/", tasks_create_file),
    path("apiv2/tasks/list/<int:limit>/<int:offset>/", tasks_list),
    path("apiv2/tasks/view/<int:task_id>/", tasks_view),
]


# ---------- tests ----------------------------------------------------

@pytest.fixture(scope="module")
def schema():
    generator = SchemaGenerator()
    return generator.get_schema(request=None, public=True)


class TestSchemaShape:
    def test_is_openapi_3(self, schema):
        assert schema["openapi"].startswith("3."), schema["openapi"]

    def test_info_block_present(self, schema):
        assert "info" in schema
        assert schema["info"]["title"] == "Test"
        assert schema["info"]["version"] == "0.0.0"

    def test_has_paths(self, schema):
        paths = set(schema["paths"].keys())
        assert "/apiv2/tasks/create/file/" in paths
        assert "/apiv2/tasks/view/{task_id}/" in paths
        assert "/apiv2/tasks/list/{limit}/{offset}/" in paths


class TestOperations:
    def test_post_endpoint_has_post_operation(self, schema):
        op = schema["paths"]["/apiv2/tasks/create/file/"]["post"]
        assert op["summary"] == "Submit a file"
        assert "Tasks" in op["tags"]

    def test_get_endpoint_has_get_operation(self, schema):
        op = schema["paths"]["/apiv2/tasks/view/{task_id}/"]["get"]
        assert op["summary"] == "Get one task"
        # task_id from the URL is captured as a path parameter.
        names = {p["name"] for p in op.get("parameters", [])}
        assert "task_id" in names

    def test_extra_path_parameters_propagate(self, schema):
        op = schema["paths"]["/apiv2/tasks/list/{limit}/{offset}/"]["get"]
        names = {p["name"] for p in op.get("parameters", [])}
        assert {"limit", "offset"}.issubset(names)


class TestSerialization:
    def test_json_round_trips(self, schema):
        # The schema is the canonical wire format -- it must json.dumps
        # without exceptions or non-serializable defaults.
        encoded = json.dumps(schema)
        decoded = json.loads(encoded)
        assert decoded["openapi"] == schema["openapi"]
