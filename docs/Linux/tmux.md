# Session Control (from the command line)

| `tmux`                                  | Start a new session                                         |
| --------------------------------------- | ----------------------------------------------------------- |
| `tmux new -s <session-name>`            | Start a new session with the name chosen                    |
| `tmux ls`                               | List all sessions                                           |
| `tmux attach -t <target-session>`       | Re-attach a detached session                                |
| `tmux attach -d -t <target-session>`    | Re-attach a detached session (and detach it from elsewhere) |
| `tmux kill-session -t <target-session>` | Delete session                                              |

# Pane Control

| `Ctrl` `b`, `"`        | Split pane horizontally                  |
| ---------------------- | ---------------------------------------- |
| `Ctrl` `b`, `%`        | Split pane vertically                    |
| `Ctrl` `b`, `o`        | Next pane                                |
| `Ctrl` `b`, `;`        | Previous pane                            |
| `Ctrl` `b`, `q`        | Show pane numbers                        |
| `Ctrl` `b`, `z`        | Toggle pane zoom                         |
| `Ctrl` `b`, `!`        | Convert pane into a window               |
| `Ctrl` `b`, `x`        | Kill current pane                        |
| `Ctrl` `b`, `Ctrl` `O` | Swap panes                               |
| `Ctrl` `b`, `t`        | Display clock                            |
| `Ctrl` `b`, `q`        | Transpose two letters (delete and paste) |
| `Ctrl` `b`, `{`        | Move to the previous pane                |
| `Ctrl` `b`, `}`        | Move to the next pane                    |
| `Ctrl` `b`, `Space`    | Toggle between pane layouts              |
| `Ctrl` `b`, `↑`        | Resize pane (make taller)                |
| `Ctrl` `b`, `↓`        | Resize pane (make smaller)               |
| `Ctrl` `b`, `←`        | Resize pane (make wider)                 |
| `Ctrl` `b`, `→`        | Resize pane (make narrower               |

# Window Control

| `Ctrl` `b`, `c` | Create new window     |
| --------------- | --------------------- |
| `Ctrl` `b`, `d` | Detach from session   |
| `Ctrl` `b`, `,` | Rename current window |
| `Ctrl` `b`, `&` | Close current window  |
| `Ctrl` `b`, `w` | List [[windows]]          |
| `Ctrl` `b`, `p` | Previous window       |
| `Ctrl` `b`, `n` | Next window           |

# Copy-Mode (vi)

| `Ctrl` `b`, `[`     | Enter copy mode   |
| ------------------- | ----------------- |
| `Ctrl` `b`, `G`     | Bottom of history |
| `Ctrl` `b`, `g`     | Top of history    |
| `Ctrl` `b`, `Enter` | Copy selection    |
| `Ctrl` `b`, `p`     | Paste selection   |
| `Ctrl` `b`, `k`     | Cursor Up         |
| `Ctrl` `b`, `j`     | Cursor Down       |
| `Ctrl` `b`, `h`     | Cursor Left       |
| `Ctrl` `b`, `l`     | Cursor Right      |
