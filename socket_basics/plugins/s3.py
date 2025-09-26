import os
import subprocess
import logging
from typing import Optional, Tuple

try:
    from light_s3_client import Client
    S3_AVAILABLE = True
except Exception:
    Client = None
    S3_AVAILABLE = False


def _is_s3_enabled() -> bool:
    return (
        S3_AVAILABLE and
        bool(os.environ.get('SOCKET_S3_ENABLED', '').lower() in ('true', '1', 'yes')) and
        bool(os.environ.get('SOCKET_S3_BUCKET')) and
        bool(os.environ.get('SOCKET_S3_ACCESS_KEY')) and
        bool(os.environ.get('SOCKET_S3_SECRET_KEY'))
    )


def _init_s3_client():
    if Client is None:
        return None
    try:
        endpoint = os.environ.get('SOCKET_S3_ENDPOINT')
        region = os.environ.get('SOCKET_S3_REGION', 'us-east-1')
        access_key = os.environ.get('SOCKET_S3_ACCESS_KEY')
        secret_key = os.environ.get('SOCKET_S3_SECRET_KEY')

        if endpoint:
            return Client(server=endpoint, region=region, access_key=access_key, secret_key=secret_key)
        else:
            return Client(region=region, access_key=access_key, secret_key=secret_key)
    except Exception:
        return None


def _get_git_commit_hash(workspace_path: str = '.') -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=workspace_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _get_repo_branch_name(workspace_path: str = '.') -> Tuple[str, str]:
    """Return (repository, branch) with fallbacks to environment variables."""
    env_repo = os.environ.get('SOCKET_REPOSITORY_NAME') or os.environ.get('GITHUB_REPOSITORY')
    env_branch = os.environ.get('SOCKET_BRANCH_NAME') or os.environ.get('GITHUB_REF_NAME')

    repository = None
    branch = None

    if env_repo:
        repository = env_repo.split('/')[-1] if '/' in env_repo else env_repo

    if env_branch:
        branch = env_branch

    # Try git if not provided
    if not repository:
        try:
            result = subprocess.run(["git", "remote", "get-url", "origin"], cwd=workspace_path, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                remote_url = result.stdout.strip()
                if remote_url.endswith('.git'):
                    remote_url = remote_url[:-4]
                repository = remote_url.split('/')[-1]
        except Exception:
            repository = 'unknown-repo'

    if not branch:
        try:
            result = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=workspace_path, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                br = result.stdout.strip()
                if br == 'HEAD':
                    # detached
                    branch = os.environ.get('GITHUB_HEAD_REF') or (os.environ.get('GITHUB_REF').replace('refs/heads/', '') if os.environ.get('GITHUB_REF') else 'detached-head')
                else:
                    branch = br
        except Exception:
            branch = 'unknown-branch'

    return repository or 'unknown-repo', branch or 'unknown-branch'


def upload_output_file(output_path: str, workspace_path: str = '.') -> bool:
    """Upload the provided output file to S3 at bucket/repo/branch/commit/FILE.

    Returns True on success, False otherwise.
    """
    logger = logging.getLogger(__name__)
    if not _is_s3_enabled():
        logger.info("S3 upload not enabled or S3 client unavailable; skipping upload")
        return False

    client = _init_s3_client()
    if not client:
        logger.warning("Failed to initialize S3 client; skipping upload")
        return False

    bucket = os.environ.get('SOCKET_S3_BUCKET')

    repository, branch = _get_repo_branch_name(workspace_path)
    commit = _get_git_commit_hash(workspace_path) or 'no-commit'

    filename = os.path.basename(output_path)
    s3_key = f"{repository}/{branch}/{commit}/{filename}"

    try:
        # Read file bytes
        with open(output_path, 'rb') as f:
            data = f.read()

        success = client.upload_fileobj(data, bucket, s3_key)

        # light_s3_client.upload_fileobj may return a requests.Response or a boolean
        try:
            status_code = getattr(success, 'status_code', None)
            if status_code is not None:
                if 200 <= int(status_code) < 300:
                    logger.info(f"Uploaded {output_path} to s3://{bucket}/{s3_key}")
                    return True
                else:
                    body = getattr(success, 'text', repr(success))
                    logger.warning(f"Upload returned HTTP {status_code}: {body}")
                    return False

            # Otherwise treat truthy values as success
            if success:
                logger.info(f"Uploaded {output_path} to s3://{bucket}/{s3_key}")
                return True
            else:
                logger.warning(f"Failed to upload {output_path} to s3://{bucket}/{s3_key}")
                return False
        except Exception as e:
            logger.exception("Error checking upload response: %s", e)
            return False
    except Exception as e:
        logger.exception("Error uploading file to S3: %s", e)
        return False
