- Installing tmux
	`sudo apt install -y tmux`
		* will be different based on your Linux distro
- Built in Help menu for all tmux commands
	`ctrl+b+?`
	`q` to quit
- Manage Tmux Sessions
	- Start a new tmux session
		`tmux`
		`tmux new -s <session-name>`
	- Rename the current tmux Session
		`ctrl+b+$`
			* Retype session name and save with the enter-key
	- Swap between different sessions within the current session
		`ctrl+b+s`
			* Arrow key up/down and select session with the enter-key
	- Detach and Attach to a active tmux session without closing it
		1. Detach from the current tmux session
			`ctrl+b+d`
		2. Attach to a active tmux session
			`tmux a`
			`tmux a -t <tmux-session-name>`
		- Double check for any active tmux sessions
			`tmux ls`
			`tmux list-sessions`
- Manage Tmux Windows
	- Swap between tmux windows
		`ctrl+b+n` 0r `ctrl+b+p`
		`ctrl+b+w`
			* Arrow key up/down and select tmux window with the enter-key
		- Swap between the <2> last used tmux windows
				`ctrl+b+l`
	- Rename the currently selected tmux window
		`ctrl+b+,`
			* Retype name and save with the enter-key
- Manage Tmux Panes
	- Split tmux panes Horizontally
		`ctrl+b+"`
	- Split tmux panes Vertically
		`ctrl+b+%`
	- Detach a tmux pane into its own tmux window
		`ctrl+b+!`
	- Zoom into a tmux pane without spliting it into its own window
		`ctrl+b+z`
		`ctrl+b+z`
			* "Same command again to undo the zoom in"
	- Move between different tmux panes in the same tmux window
		1. With Arrow Keys
			`ctrl+b`
				* Move to the pane you want to select/use with the arrow keys
		2. Between the 2 last used tmux panes
			`ctrl+b+;`
		3. cycle between all tmux panes
			`ctrl+b+o`
		4. Using the q -> pane number method
			`ctrl+b+q`
			- select the pane by pressing the number of that window
- Grep/Search for Text up or down the page
	- Search `<Up>` the page
		1. Enter Scroll Mode
			`ctrl+b+[`
		2. Search Up the page
			`ctrl+r`
				* Do `ctrl+r` again to keep searching up the page
				* Go back into Scroll mode next to the text you found in grep/search mode without going to back to the bottom
					`Enter-Key`
	- Search `<Down>` the page
		1. Enter Scroll Mode
			`ctrl+b+[`
		2. Search Down the page
			`ctrl+s`
				* Do `ctrl+s` again to keep searching down the page
				* Go back into Scroll mode next to the text you found in grep/search mode without going to back to the bottom
					`Enter-Key`
- Copy and Paste walls of text in tmux to the tmux buffer
	1. Enter Copy/Scroll Mode
		`ctrl+b+[`
	2. Enable highlighting
		`ctrl+spacebar`
	3. Copy highlighted text to tmux clipboard
		`alt+w`
	4. Paste what is copied to the tmux clip board
		`ctrl+b+]`
	5. Extra (check what is copied to the tmux clipboard before pasting)
		`ctrl+b+shift+#`
		`q` to quit