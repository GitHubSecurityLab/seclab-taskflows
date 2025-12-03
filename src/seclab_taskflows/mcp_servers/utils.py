# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

def process_repo(owner, repo):
    """
    Normalize repository identifier to lowercase format 'owner/repo'.

    Args:
        owner (str): The owner of the repository.
        repo (str): The name of the repository.

    Returns:
        str: The normalized repository identifier in lowercase.
    """
    return f"{owner}/{repo}".lower()
