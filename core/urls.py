from django.contrib import admin
from django.urls import include, path

from api.openapi import OpenAPISchemaView, RedocUIView, SwaggerUIView
from api.views import HealthCheckView

urlpatterns = [
    path("", HealthCheckView.as_view(), name="root-health"),
    path("schema/", OpenAPISchemaView.as_view(), name="root-openapi-schema"),
    path("docs/", SwaggerUIView.as_view(), name="root-swagger-docs"),
    path("swagger/", SwaggerUIView.as_view(), name="root-swagger-ui"),
    path("redoc/", RedocUIView.as_view(), name="root-redoc"),
    path("admin/", admin.site.urls),
    path("api/", include("api.urls", namespace="api")),
]
