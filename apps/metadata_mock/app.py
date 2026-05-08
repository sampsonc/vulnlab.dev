"""Mock AWS IMDSv1 service.

Bound to 169.254.169.254:80 (the same address real AWS instances use). Real
SSRF tools sending IMDS-aware payloads will hit something realistic.

Simulates IMDSv1 only on purpose — IMDSv2 requires a PUT-issued token, which
GET-only SSRF can't obtain. Demonstrating that asymmetry is part of the point.
"""
from __future__ import annotations

import json

from flask import Flask, Response, jsonify

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

    @app.errorhandler(404)
    def nf(_e):
        return text("Not Found\n"), 404

    return app


app = create_app()
