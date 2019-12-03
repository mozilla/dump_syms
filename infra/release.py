# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from github import Github
import os
import tarfile
import requests


def mk_archive(name):
    base_dir = f"{name}-linux-x86_64"
    arch_name = f"{base_dir}.tar.gz"
    path = os.path.join("target", "release", name)
    dest = os.path.join(base_dir, name)
    with tarfile.open(arch_name, "w:gz") as tar:
        tar.add(path, arcname=dest)
        return arch_name


def get_github_token(name):
    r = requests.get(
        f"{os.environ['TASKCLUSTER_PROXY_URL']}/secrets/v1/secret/project/relman/{name}/deploy"
    )
    r.raise_for_status()
    data = r.json()

    return data["github"]["token"]


def upload(name):
    token = get_github_token(name)
    g = Github(token)
    repo = g.get_repo(f"mozilla/{name}")
    release = repo.get_latest_release()
    path = mk_archive(name)

    release.upload_asset(path=path, content_type="application/octet-stream")


if __name__ == "__main__":
    upload(f"{os.environ['PROJECT_NAME']}")
