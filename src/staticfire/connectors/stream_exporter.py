from urllib.parse import urlsplit

from staticfire.connector_vendors import ConnectorSpec


def _env(fake) -> dict[str, str]:
    # minio-py ignores the proxy variables: the connector talks to ofapi directly, which
    # serves S3 for the buckets named sfminio-* (ofapi's minio_s3 module)
    ofapi = urlsplit(fake.http_url())
    return {
        "MINIO_ENDPOINT": ofapi.hostname,
        "MINIO_PORT": str(ofapi.port),
        "MINIO_BUCKET": "sfminio-stream-export",
        "MINIO_FOLDER": "opencti-stream",
        "MINIO_ACCESS_KEY": "staticfire",
        "MINIO_SECRET_KEY": "staticfire-fake-key",
        "MINIO_SECURE": "false",
        "MINIO_CERT_CHECK": "false",
        "WRITE_EVERY_SEC": "10",
    }


SPEC = ConnectorSpec(
    recipe="stream-exporter",
    connector="stream/stream-exporter",
    env=_env,
    proxy=False,
    calls=["/sfminio-stream-export"],
    description="the stream events of new objects are written as a JSON-lines file to the "
    "bucket (an S3 emulation of ofapi standing in for MinIO)",
)
