# Rabjho-Rambles

## Tutorial: Adding New Posts & Hosting Locally

### Creating a New Post

Use Hugo's built-in command to create a new post with the proper structure:

```bash
hugo new post/my-awesome-post/index.md
```

This creates the directory and file with frontmatter from the archetype template.

### Frontmatter Template

Add this to the top of `index.md` (there should already be a placeholder):

```toml
+++
date = '2026-04-28T09:00:00Z'
draft = false
slug = 'my-awesome-post'
title = 'My Awesome Post Title'
author = ["Your Name"]
tags = ["tag1", "tag2"]
ctf = "CTF Name (optional)"
image = "image-filename.png (optional)"
+++
```

**Fields:**

- `date`: ISO 8601 format
- `draft`: Set to `false` to publish, `true` to keep as draft
- `slug`: URL-friendly identifier (must match directory name)
- `title`: Post title
- `author`: Array of author names
- `tags`: Array of tags (e.g., "rev", "pwn", "web")
- `ctf`: CTF name if applicable (optional)
- `image`: Featured image filename (optional)

### Writing Content

After the `+++`, write in Markdown:

```markdown
## Section

Your content here with **bold**, _italic_, `code`, etc.

### Subsection

More content...
```

### Adding Images

Place images in the same directory as `index.md`:

```
content/post/my-awesome-post/
├── index.md
└── my-image.png
```

Reference them as: `![Alt text](my-image.png)`

### Hosting Locally

Start the dev server from the repo root:

```bash
hugo server --bind 0.0.0.0
```

Or with drafts:

```bash
hugo server -D --bind 0.0.0.0
```

Visit `http://localhost:1313` in your browser. Changes auto-refresh.

Stop with `Ctrl+C`.

### Publishing

When ready:

1. Change `draft = false` in frontmatter
2. Push to github
