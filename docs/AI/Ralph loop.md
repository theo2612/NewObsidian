'while ! npm test; do git diff | claude code "Fix failing tests using this diff and test output"; done'

https://www.youtube.com/watch?v=Yr9O6KFwbW4
https://www.youtube.com/watch?v=4Nna09dG_c0
https://ghuntley.com/ralph/

https://x.com/ryancarson/status/2008548371712135632
  
Everyone is raving about Ralph. What is it?

Ralph is an autonomous AI coding loop that ships features while you sleep.

Created by

and announced in

, it runs

(or your agent of choice) repeatedly until all tasks are complete.

Each iteration is a fresh context window (keeping Threads nice and small). Memory persists via git history and text files.

I ran it for the first time and shipped a feature last night. I love it.

Ryan Carson

![](https://pbs.twimg.com/profile_images/1995950801706254336/0MorviXJ_bigger.jpg)

Didn't even get to bed yet. Already done. Impressed.

[

![Image](https://pbs.twimg.com/media/G981xxqW0AAJvcc?format=jpg&name=small)

]([https://x.com/ryancarson/status/2008383176339579040/photo/1](https://x.com/ryancarson/status/2008383176339579040/photo/1))

Quote

Ryan Carson

![](https://pbs.twimg.com/profile_images/1995950801706254336/0MorviXJ_bigger.jpg)

![Willy Wonka Suspense GIF](https://pbs.twimg.com/tweet_video_thumb/G98lIC-W8AAlsfa?format=jpg&name=240x240)

Going to kick off a Ralph session in Amp tonight to see if it can build a pretty complete feature while I sleep. Currently chatting with Amp to build the PR, which we'll use to populate the user stories json. Then I'll start the script and go to bed.

(Here's a

for you to download and try.)

1. Pipes a prompt into your AI agent
2. Agent picks the next story from prd.json
3. Agent implements it
4. Agent runs typecheck + tests
5. Agent commits if passing
6. Agent marks story done
7. Agent logs learnings
8. Loop repeats until done


Memory persists only through:

- Git commits  
    
- progress.txt (learnings)  
    
- prd.json (task status)  
    

```
scripts/ralph/
├── ralph.sh
├── prompt.md
├── prd.json
└── progress.txt
```

```
#!/bin/bash
set -e

MAX_ITERATIONS=${1:-10}
SCRIPT_DIR="$(cd "$(dirname \
  "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Starting Ralph"

for i in $(seq 1 $MAX_ITERATIONS); do
  echo "═══ Iteration $i ═══"
  
  OUTPUT=$(cat "$SCRIPT_DIR/prompt.md" \
    | amp --dangerously-allow-all 2>&1 \
    | tee /dev/stderr) || true
  
  if echo "$OUTPUT" | \
    grep -q "<promise>COMPLETE</promise>"
  then
    echo "✅ Done!"
    exit 0
  fi
  
  sleep 2
done

echo "⚠️ Max iterations reached"
exit 1
```

```
chmod +x scripts/ralph/ralph.sh
```

- Claude Code: `claude --dangerously-skip-permissions`  
    

Instructions for each iteration:

```
# Ralph Agent Instructions

## Your Task

1. Read `scripts/ralph/prd.json`
2. Read `scripts/ralph/progress.txt`
   (check Codebase Patterns first)
3. Check you're on the correct branch
4. Pick highest priority story 
   where `passes: false`
5. Implement that ONE story
6. Run typecheck and tests
7. Update AGENTS.md files with learnings
8. Commit: `feat: [ID] - [Title]`
9. Update prd.json: `passes: true`
10. Append learnings to progress.txt

## Progress Format

APPEND to progress.txt:

## [Date] - [Story ID]
- What was implemented
- Files changed
- **Learnings:**
  - Patterns discovered
  - Gotchas encountered
---

## Codebase Patterns

Add reusable patterns to the TOP 
of progress.txt:

## Codebase Patterns
- Migrations: Use IF NOT EXISTS
- React: useRef<Timeout | null>(null)

## Stop Condition

If ALL stories pass, reply:
<promise>COMPLETE</promise>

Otherwise end normally.
```

```
{
  "branchName": "ralph/feature",
  "userStories": [
    {
      "id": "US-001",
      "title": "Add login form",
      "acceptanceCriteria": [
        "Email/password fields",
        "Validates email format",
        "typecheck passes"
      ],
      "priority": 1,
      "passes": false,
      "notes": ""
    }
  ]
}
```

- `branchName` — branch to use  
    
- `priority` — lower = first  
    
- `passes` — set true when done  
    

```
# Ralph Progress Log
Started: 2024-01-15

## Codebase Patterns
- Migrations: IF NOT EXISTS
- Types: Export from actions.ts

## Key Files
- db/schema.ts
- app/auth/actions.ts
---
```

Ralph appends after each story.

Patterns accumulate across iterations.

```
./scripts/ralph/ralph.sh 25
```

Runs up to 25 iterations.

- Create the feature branch  
    
- Complete stories one by one  
    
- Commit after each  
    
- Stop when all pass  
    

Must fit in one context window.

```
❌ Too big:
> "Build entire auth system"
✅ Right size:
> "Add login form"
> "Add email validation"
> "Add auth server action"
```

Ralph needs fast feedback:

- `npm run typecheck`  
    
- `npm test`  
    

Without these, broken code compounds.

```
❌ Vague:
> "Users can log in"
✅ Explicit:
> - Email/password fields
> - Validates email format
> - Shows error on failure
> - typecheck passes
> - Verify at localhost:$PORT/login (PORT defaults to 3000)
```

By story 10, Ralph knows patterns from stories 1-9.

Two places for learnings:

1. progress.txt — session memory for Ralph iterations
2. — permanent docs for humans and future agents

Before committing, Ralph updates

files in directories with edited files if it discovered reusable patterns (gotchas, conventions, dependencies).

Ralph updates

when it learns something worth preserving:

```
✅ Good additions:
- "When modifying X, also update Y"
- "This module uses pattern Z"
- "Tests require dev server running"
❌ Don't add:
- Story-specific details
- Temporary notes
- Info already in progress.txt
```

For UI changes, use the

by

. Load it with `Load the dev-browser skill`, then:

```
# Start the browser server
~/.config/amp/skills/dev-browser/server.sh &
# Wait for "Ready" message

# Write scripts using heredocs
cd ~/.config/amp/skills/dev-browser && npx tsx <<'EOF'
import { connect, waitForPageLoad } from "@/client.js";

const client = await connect();
const page = await client.page("test");
await page.setViewportSize({ width: 1280, height: 900 });
const port = process.env.PORT || "3000";
await page.goto(`http://localhost:${port}/your-page`);
await waitForPageLoad(page);
await page.screenshot({ path: "tmp/screenshot.png" });
await client.disconnect();
EOF
```

Not complete until verified with screenshot.

```
ADD COLUMN IF NOT EXISTS email TEXT;
```

```
echo -e "\n\n\n" | npm run db:generate
```

After editing schema, check:

- Server actions  
    
- UI components  
    
- API routes  
    

Fixing related files is OK:

If typecheck requires other changes, make them. Not scope creep.

```
# Story status
cat scripts/ralph/prd.json | \
jq '.userStories[] | {id, passes}'
# Learnings
cat scripts/ralph/progress.txt
# Commits
git log --oneline -10
```

We built an evaluation system:

- 13 user stories  
    
- ~15 iterations  
    
- 2-5 min each  
    
- ~1 hour total  
    

Learnings compound. By story 10, Ralph knew our patterns.

- Exploratory work  
    
- Major refactors without criteria  
    
- Security-critical code  
    
- Anything needing human review  
    

For a great video walkthrough of how to use Ralph, checkout the video from

...

My Ralph Wiggum breakdown went viral. It's a keep-it-simple-stupid approach to AI coding that lets you ship while you sleep. So here's a full explanation, example code, and demo.

![](https://pbs.twimg.com/amplify_video_thumb/2008199065901703168/img/RL13KJK9DQjyi8iI.jpg)