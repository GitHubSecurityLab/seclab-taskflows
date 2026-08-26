# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import functools


def normalize_repo(repo):
    """Canonical form of a repository identifier: stripped and lowercased.

    Every per-repo lookup and cross-repo guard in the audit v2 stores compares
    repo strings directly, so they all have to agree on one spelling. Doing the
    normalisation here, at the boundary that owns the data, keeps that
    invariant from depending on every caller remembering to lowercase first.
    """
    return (repo or "").strip().lower()


def process_repo(owner, repo):
    """Normalize an owner/repo pair into the canonical 'owner/repo' identifier.

    Args:
        owner (str): The owner of the repository.
        repo (str): The name of the repository.

    Returns:
        str: The normalized repository identifier in lowercase.
    """
    return normalize_repo(f"{(owner or '').strip()}/{(repo or '').strip()}")


def normalizes_repo(method):
    """Normalize the ``repo`` argument of a backend method before it runs.

    The audit v2 stores key every write, read and cross-repo guard off the repo
    string, so a caller that passes a differently cased or padded spelling would
    silently write findings no later stage can read back, or defeat the
    per-repo guards. Applying this at the method boundary makes the store,
    rather than each caller, responsible for the invariant.
    """

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if "repo" in kwargs:
            kwargs["repo"] = normalize_repo(kwargs["repo"])
        elif args:
            args = (normalize_repo(args[0]), *args[1:])
        return method(self, *args, **kwargs)

    return wrapper
