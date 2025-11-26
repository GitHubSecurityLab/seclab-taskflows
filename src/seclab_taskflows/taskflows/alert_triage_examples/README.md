## Triage taskflows

This directory contains taskflows for fetching code scanning alerts from a repo and triaging them using a set of criteria. The taskflow for triaging a specific type of alerts starts with `triage_*`. To use these taskflows, modify the `create repo list` step and insert the actual repo that you'd like to run the taskflow on:

```yaml
  - task:
      must_complete: true
      exclude_from_context: true
      agents:
        - assistant
      name: create repo list
      description: create repo list to fetch alerts from.
      run: |
        echo '[ {"repo": ""}]'  #<--------- change this to actual repo (or a list of repos)

```

After running the triage workflows, the analysis results are stored in a sqlite3 database called `alert_results.db` in the `ALERT_RESULTS_DIR`.

To generate a report and create an issue in the repository, run the corresponding `create_issue_*` taskflows. For example, `js` related issues are created with `create_issue_js_ts.yaml` and `actions` related issues are created with `create_issues_actions.yaml`. When using these taskflows, the `github_official` mcp server is used and an authorization token needs to be set:

```
GITHUB_AUTH_HEADER="Bearer <my_token>"
```

After creating an issue, additional triaging checks are applied to remove false positives by running the corresponding `review_*` taskflows.
