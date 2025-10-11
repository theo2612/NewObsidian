
- while in discord `ctrl-i`
- console
- paste below
```bash
(() => {
  const group = document.querySelector('[role="group"][aria-label="Servers"]');
  if (!group) return;

  const sidebar = group.closest('nav') || group.parentElement;
  const items = group.querySelectorAll(':scope > .listItem__650eb').length
      ? [...group.querySelectorAll(':scope > .listItem__650eb')]
      : [...group.querySelectorAll(':scope > div')];

  if (items.length < 2) return;

  if (sidebar) {
    sidebar.style.width = "90px";
    sidebar.style.transition = "width 0.2s ease";
  }

  const row = document.createElement("div");
  row.id = "__discordTwoWideRow";
  const gap = getComputedStyle(group).gap || "8px";
  Object.assign(row.style, {display: "flex", flexDirection: "row", alignItems: "center", columnGap: gap, marginBottom: gap});
  group.insertBefore(row, items[0]);
  [items[0], items[1]].forEach(el => (el.style.margin = "0"));
  row.append(items[0], items[1]);
})();
```