// Plain JS (no build step). Renders `links` ({ label: href }) as a list in the sidebar.
// Hrefs starting with "/" are site pages; anything else opens as an external link.
import { h } from "preact"

const css = `
.sidebar-links {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.sidebar-links a {
  font-weight: 600;
  color: var(--darkgray);
  background: none;
}
.sidebar-links a:hover,
.sidebar-links a.active {
  color: var(--secondary);
}
/* phones: the sidebar is a header row; put the links on their own row below it */
@media (max-width: 800px) {
  .sidebar-links {
    order: 10;
    flex-basis: 100%;
    flex-direction: row;
    justify-content: center;
    gap: 1.5rem;
    padding: 0.75rem 0 0.25rem;
  }
}
`

export const SidebarLinks = (opts) => {
  const links = Object.entries(opts?.links ?? {})

  const Component = ({ fileData, displayClass }) => {
    const current = "/" + (fileData.slug ?? "").replace(/(^|\/)index$/, "")
    return h(
      "ul",
      { class: ["sidebar-links", displayClass].filter(Boolean).join(" ") },
      links.map(([label, href]) => {
        const external = !href.startsWith("/")
        const active = !external && (current === href || current.startsWith(href + "/"))
        return h(
          "li",
          null,
          h(
            "a",
            {
              href,
              class: active ? "active" : undefined,
              ...(external ? { target: "_blank", rel: "noopener noreferrer" } : {}),
            },
            label,
          ),
        )
      }),
    )
  }

  Component.css = css
  // Workaround for the explorer plugin: on a fresh visit it calls scrollIntoView() on the
  // active post, which scrolls the whole page (down on desktop, sideways on phones). It
  // skips that when a saved explorer scroll position exists, so seed one.
  Component.beforeDOMLoaded = `try {
    if (sessionStorage.getItem("explorerScrollTop") === null) sessionStorage.setItem("explorerScrollTop", "0")
  } catch {}`
  return Component
}
