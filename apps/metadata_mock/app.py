"""Mock cloud-instance metadata service (AWS + GCP + Azure).

Bound to 169.254.169.254:80, the link-local address all three providers
use. Routing is path-based; GCP and Azure additionally require their
provider-specific request header, matching production behavior.

Simulates IMDSv1 only on purpose — IMDSv2 requires a PUT-issued token, which
GET-only SSRF can't obtain. Demonstrating that asymmetry is part of the point.
"""
from __future__ import annotations

import json

from flask import Flask, Response, jsonify, request

ROLE = "vulnlab-imds-test-role"
INSTANCE_ID = "i-0deadbeef0123abcd"
REGION = "us-east-1"
AZ = "us-east-1a"

FAKE_CREDENTIALS = {
    "Code": "Success",
    "LastUpdated": "2026-05-08T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "VULNLAB-FAKE-TOKEN-NOT-A-REAL-CREDENTIAL",
    "Expiration": "2099-12-31T23:59:59Z",
}


def text(body: str) -> Response:
    return Response(body, mimetype="text/plain")


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def root():
        return text("latest\n")

    @app.get("/latest/")
    def latest():
        return text("dynamic\nmeta-data\nuser-data\n")

    @app.get("/latest/meta-data/")
    def meta_data_index():
        return text(
            "ami-id\n"
            "hostname\n"
            "iam/\n"
            "instance-id\n"
            "instance-type\n"
            "local-ipv4\n"
            "mac\n"
            "placement/\n"
            "public-hostname\n"
            "public-ipv4\n"
            "security-groups\n"
        )

    @app.get("/latest/meta-data/instance-id")
    def instance_id():
        return text(INSTANCE_ID)

    @app.get("/latest/meta-data/instance-type")
    def instance_type():
        return text("t3.medium")

    @app.get("/latest/meta-data/ami-id")
    def ami_id():
        return text("ami-0abcdef1234567890")

    @app.get("/latest/meta-data/hostname")
    def hostname():
        return text("ip-10-0-1-23.ec2.internal")

    @app.get("/latest/meta-data/local-ipv4")
    def local_ipv4():
        return text("10.0.1.23")

    @app.get("/latest/meta-data/public-ipv4")
    def public_ipv4():
        return text("203.0.113.42")

    @app.get("/latest/meta-data/public-hostname")
    def public_hostname():
        return text("ec2-203-0-113-42.compute-1.amazonaws.com")

    @app.get("/latest/meta-data/mac")
    def mac():
        return text("0e:1a:2b:3c:4d:5e")

    @app.get("/latest/meta-data/security-groups")
    def security_groups():
        return text("vulnlab-default\n")

    @app.get("/latest/meta-data/placement/")
    def placement_index():
        return text("availability-zone\nregion\n")

    @app.get("/latest/meta-data/placement/availability-zone")
    def az():
        return text(AZ)

    @app.get("/latest/meta-data/placement/region")
    def region():
        return text(REGION)

    @app.get("/latest/meta-data/iam/")
    def iam_index():
        return text("info\nsecurity-credentials/\n")

    @app.get("/latest/meta-data/iam/info")
    def iam_info():
        return jsonify(
            Code="Success",
            LastUpdated="2026-05-08T00:00:00Z",
            InstanceProfileArn=f"arn:aws:iam::123456789012:instance-profile/{ROLE}",
            InstanceProfileId="AIPAEXAMPLEEXAMPLEEX",
        )

    @app.get("/latest/meta-data/iam/security-credentials/")
    def creds_index():
        return text(ROLE + "\n")

    @app.get(f"/latest/meta-data/iam/security-credentials/{ROLE}")
    def creds_role():
        return Response(json.dumps(FAKE_CREDENTIALS, indent=2), mimetype="application/json")

    @app.get("/latest/user-data")
    def user_data():
        return text(
            "#!/bin/bash\n"
            "# example user-data — pretend secrets in here\n"
            "export DB_PASSWORD='hunter2-vulnlab-fake'\n"
            "export ADMIN_TOKEN='VULNLAB{user-data-leaked-via-ssrf}'\n"
        )

    @app.get("/latest/api/token")
    def imdsv2_token():
        # IMDSv2 requires PUT with a TTL header. We respond 405 to GETs.
        return Response("", status=405)

    # --- GCP (Compute Engine / Cloud Run / GKE) ---
    # Real GCE returns 403 unless 'Metadata-Flavor: Google' is set. Tools that
    # don't know to add it (or apps whose SDK doesn't add it) hit this guard.
    GCP_PROJECT = "vulnlab-fake-project"
    GCP_SA_EMAIL = "vulnlab-sa@vulnlab-fake-project.iam.gserviceaccount.com"
    GCP_FAKE_TOKEN = {
        "access_token": "ya29.VULNLAB-FAKE-GCP-OAUTH2-TOKEN-NOT-REAL",
        "expires_in": 3599,
        "token_type": "Bearer",
    }

    def _require_gcp_header():
        if request.headers.get("Metadata-Flavor") != "Google":
            return text("Missing Metadata-Flavor:Google header.\n"), 403
        return None

    @app.get("/computeMetadata/v1/")
    def gcp_root():
        if (err := _require_gcp_header()) is not None:
            return err
        return text("instance/\nproject/\n")

    @app.get("/computeMetadata/v1/project/project-id")
    def gcp_project_id():
        if (err := _require_gcp_header()) is not None:
            return err
        return text(GCP_PROJECT)

    @app.get("/computeMetadata/v1/instance/")
    def gcp_instance_index():
        if (err := _require_gcp_header()) is not None:
            return err
        return text("hostname\nid\nmachine-type\nservice-accounts/\nzone\n")

    @app.get("/computeMetadata/v1/instance/id")
    def gcp_instance_id():
        if (err := _require_gcp_header()) is not None:
            return err
        return text("8675309000000000001")

    @app.get("/computeMetadata/v1/instance/hostname")
    def gcp_hostname():
        if (err := _require_gcp_header()) is not None:
            return err
        return text(f"vulnlab-vm.c.{GCP_PROJECT}.internal")

    @app.get("/computeMetadata/v1/instance/zone")
    def gcp_zone():
        if (err := _require_gcp_header()) is not None:
            return err
        return text(f"projects/123456789/zones/us-central1-a")

    @app.get("/computeMetadata/v1/instance/service-accounts/")
    def gcp_sa_index():
        if (err := _require_gcp_header()) is not None:
            return err
        return text("default/\n")

    @app.get("/computeMetadata/v1/instance/service-accounts/default/")
    def gcp_sa_default():
        if (err := _require_gcp_header()) is not None:
            return err
        return text("aliases\nemail\nscopes\ntoken\n")

    @app.get("/computeMetadata/v1/instance/service-accounts/default/email")
    def gcp_sa_email():
        if (err := _require_gcp_header()) is not None:
            return err
        return text(GCP_SA_EMAIL)

    @app.get("/computeMetadata/v1/instance/service-accounts/default/scopes")
    def gcp_sa_scopes():
        if (err := _require_gcp_header()) is not None:
            return err
        return text(
            "https://www.googleapis.com/auth/cloud-platform\n"
            "https://www.googleapis.com/auth/devstorage.read_only\n"
        )

    @app.get("/computeMetadata/v1/instance/service-accounts/default/token")
    def gcp_sa_token():
        if (err := _require_gcp_header()) is not None:
            return err
        body = dict(GCP_FAKE_TOKEN)
        body["_marker"] = "VULNLAB{ssrf-gcp-metadata-token-leaked}"
        return Response(json.dumps(body, indent=2), mimetype="application/json")

    # --- Azure (App Service / VM / AKS) ---
    # Real Azure IMDS requires 'Metadata: true' and returns 400 otherwise.
    AZURE_TENANT = "11111111-2222-3333-4444-555555555555"
    AZURE_SUB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    AZURE_FAKE_TOKEN_BASE = {
        "access_token": "VULNLAB-FAKE-AZURE-MSI-TOKEN-NOT-REAL",
        "client_id": "99999999-8888-7777-6666-555555555555",
        "expires_in": "3599",
        "expires_on": "4099161599",
        "ext_expires_in": "3599",
        "not_before": "1715000000",
        "resource": "https://management.azure.com/",
        "token_type": "Bearer",
    }

    def _require_azure_header():
        if request.headers.get("Metadata") != "true":
            body = {
                "error": "Required metadata header not specified or not valid.",
            }
            return Response(json.dumps(body), status=400, mimetype="application/json")
        return None

    @app.get("/metadata/instance")
    def azure_instance():
        if (err := _require_azure_header()) is not None:
            return err
        payload = {
            "compute": {
                "azEnvironment": "AzurePublicCloud",
                "location": "eastus",
                "name": "vulnlab-vm",
                "resourceGroupName": "vulnlab-rg",
                "subscriptionId": AZURE_SUB,
                "tenantId": AZURE_TENANT,
                "vmId": "deadbeef-1111-2222-3333-444444444444",
                "vmSize": "Standard_B2s",
            },
            "network": {
                "interface": [
                    {
                        "ipv4": {
                            "ipAddress": [{"privateIpAddress": "10.0.0.4", "publicIpAddress": "20.0.0.5"}],
                            "subnet": [{"address": "10.0.0.0", "prefix": "24"}],
                        }
                    }
                ]
            },
        }
        return Response(json.dumps(payload, indent=2), mimetype="application/json")

    @app.get("/metadata/identity/oauth2/token")
    def azure_msi_token():
        if (err := _require_azure_header()) is not None:
            return err
        body = dict(AZURE_FAKE_TOKEN_BASE)
        body["resource"] = request.args.get("resource", body["resource"])
        body["_marker"] = "VULNLAB{ssrf-azure-msi-token-leaked}"
        return Response(json.dumps(body, indent=2), mimetype="application/json")

    @app.errorhandler(404)
    def nf(_e):
        return text("Not Found\n"), 404

    return app


app = create_app()
