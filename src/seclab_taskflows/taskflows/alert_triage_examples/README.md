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

The taskflows for triaging Actions alerts are configured to triage rules with the critical severity:

```yaml
globals: 
  rule: actions/code-injection/critical
```

However, there are different versions of these rules with different severity and the taskflows can be used for triaging lower severity versions of these queries. This can be done by overwriting the rule with command line option:

```
./run_seclab_agent.sh -t seclab_taskflows.taskflows.alert_triage_examples.triage_taskflows.triage_actions_code_injection -g rule=actions/code-injection/high
```

After running the triage workflows, the analysis results are stored in a sqlite3 database called `alert_results.db` in the `DATA_DIR`.

To generate a report and create an issue in the repository, run the corresponding `create_issue_*` taskflows. For example, `js` related issues are created with `create_issue_js_ts.yaml` and `actions` related issues are created with `create_issues_actions.yaml`. When using these taskflows, the `github_official` mcp server is used and an authorization token needs to be set as the `GITHUB_AUTH_HEADER` token:

```
GITHUB_AUTH_HEADER="Bearer <my_token>"
```

After creating an issue, additional triaging checks are applied to remove false positives by running the corresponding `review_*` taskflows.

Disclaimers: 
1. Although these taskflows have already been used to report vulnerabilities to projects, we strongly recommend carefully reviewing all output. 
2. Note that running the taskflows can result in many tool calls, which can easily consume a large amount of quota. 
3. The taskflows may create GitHub issues, please be considerate and seek the repo owner’s consent before running them on somebody else’s repo.
