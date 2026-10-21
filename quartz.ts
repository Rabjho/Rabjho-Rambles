import { loadQuartzConfig, loadQuartzLayout } from "./quartz/plugins/loader/config-loader"
import { componentRegistry } from "./quartz/components/registry"
import { registerCondition } from "./quartz/plugins/loader/conditions"
import type { QuartzPluginData } from "./quartz/plugins/vfile"

// Options YAML can't express. This is what `ExternalPlugin.X({...})` does, and it must run
// before loadQuartzConfig().
// Homepage post list: only posts (by default it also lists the 404 page)
componentRegistry.setOptionOverrides("@quartz-community/recent-notes", {
  filter: (f: QuartzPluginData) => f.frontmatter?.type === "post",
})
registerCondition("index", (props) => props.fileData.slug === "index")

const config = await loadQuartzConfig()
export default config
export const layout = await loadQuartzLayout()
