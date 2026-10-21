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
// Sidebar: posts first, then the tag pages (hidden by default) as a "Tags" folder.
// These run in the browser as strings, so they can't reference anything outside themselves.
componentRegistry.setOptionOverrides("@quartz-community/explorer", {
  filterFn: () => true,
  mapFn: (node: { isFolder: boolean; slugSegment: string; displayName: string }) => {
    if (node.isFolder && node.slugSegment === "tags") node.displayName = "Tags"
  },
  sortFn: (
    a: { isFolder: boolean; displayName: string },
    b: { isFolder: boolean; displayName: string },
  ) =>
    a.isFolder === b.isFolder
      ? a.displayName.localeCompare(b.displayName, undefined, { numeric: true })
      : a.isFolder
        ? 1
        : -1,
})

const config = await loadQuartzConfig()
export default config
export const layout = await loadQuartzLayout()
