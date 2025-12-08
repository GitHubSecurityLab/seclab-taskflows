Queries in support of the CodeQL MCP Server are maintained as query packs.

If you add your own queries, please follow established conventions for normal CodeQL query pack development.

To run the CodeQL for Python server:
- create a codespace, preferably with more cores
- install CodeQL extension for VS Code
- press `Ctrl/Cmd + Shift + P` and type "CodeQL: Install Pack Dependencies". Choose "sylwia-budzynska/mcp-python" and press "OK".
- find the path to the codeql binary, which comes preinstalled with the VS Code CodeQL extension, with the command:
```bash
find ~ -type f -name codeql -executable 2>/dev/null
```
It will most likely look similar to this:
```
/home/codespace/.vscode-remote/data/User/globalStorage/github.vscode-codeql/distribution1/codeql/codeql
```
- create a folder named 'data'
- create or update your `.env` file in the root of this project with values for:
```
COPILOT_TOKEN= # a fine-grained GitHub personal access token with permission for "copilot chat"
CODEQL_DBS_BASE_PATH="/workspaces/seclab-taskflows/data/codeql_databases" # path to folder with your CodeQL databases

# Example values for a local setup, run with `python -m seclab_taskflow_agent -t seclab_taskflows.taskflows.audit.remote_sources_local`
MEMCACHE_STATE_DIR="/workspaces/seclab-taskflows/data" # path to folder for storing the memcache database
DATA_DIR="/workspaces/seclab-taskflows/data" # path to folder for storing the codeql_sqlite databases and all other data
GH_TOKEN= # can be the same token as COPILOT_TOKEN. Or another one, with access e.g. to private repositories
CODEQL_CLI= # output of command `find ~ -type f -name codeql -executable 2>/dev/null`

# Example docker env run with ./run_seclab_agent.sh [...]
# CODEQL_CLI="codeql"
# CODEQL_DBS_BASE_PATH="/app/data/codeql_databases"
# MEMCACHE_STATE_DIR="/app/data"
# DATA_DIR="/app/data"
```
