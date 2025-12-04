/**
 * @id mcp-python/remote-sources
 * @name Python Remote Sources
 * @description Identifies nodes that act as remote sources in Python code, along with their locations.
 * @tags source, location
 */
import python
import semmle.python.dataflow.new.RemoteFlowSources

// string normalizeLocation(Location l) {
//     result = l.getFile().getRelativePath() + ":" + l.getStartLine().toString() + ":" + l.getStartColumn().toString()
//     + ":" + l.getEndLine().toString() + ":" + l.getEndColumn().toString()
// }

from RemoteFlowSource source
select
  "Remote source {0} is defined at {1} line {2}",
  "source,location,line",
  source.getSourceType(),
  source.getLocation().getFile().getRelativePath(),
  source.getLocation().getStartLine().toString()
