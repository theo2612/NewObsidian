# Ralph Loop Primer

> Give this document to an AI agent to quickly set up a Ralph loop for any project.

## What is a Ralph Loop?

Ralph is an **autonomous AI coding loop** that ships features incrementally while you work on other things (or sleep).

**Key Concept:** Instead of one massive prompt, Ralph:
- Works on small, well-defined user stories one at a time
- Uses a fresh context window each iteration (stays lightweight)
- Persists memory through git commits, JSON files, and learnings
- Learns patterns and improves as it goes
- Runs tests/typecheck after each story
- Only commits when tests pass

**The Loop:**
```bash
for i in $(seq 1 MAX_ITERATIONS); do
  cat prompt.md | claude-code
  # If all stories complete, exit
  if grep -q "<promise>COMPLETE</promise>"; then exit 0; fi
done
```

## When to Use Ralph Loops

✅ **Good for:**
- Building features with clear acceptance criteria
- Repetitive implementations following patterns
- Projects with good test coverage
- Learning by watching AI work incrementally
- Non-critical/experimental code

❌ **Bad for:**
- Exploratory work without clear criteria
- Security-critical code
- Major refactors without clear goals
- Anything needing human judgment
- Production code without review

## File Structure

```
scripts/ralph/
├── ralph.sh         # The loop script
├── prompt.md        # Instructions for each iteration
├── prd.json         # User stories and status
└── progress.txt     # Learnings log
```

## Template Files

### 1. ralph.sh

```bash
#!/bin/bash
set -e

MAX_ITERATIONS=${1:-10}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Starting Ralph loop"

for i in $(seq 1 $MAX_ITERATIONS); do
  echo "═══ Iteration $i/$MAX_ITERATIONS ═══"

  OUTPUT=$(cat "$SCRIPT_DIR/prompt.md" \
    | claude code --dangerously-skip-permissions 2>&1 \
    | tee /dev/stderr) || true

  if echo "$OUTPUT" | grep -q "<promise>COMPLETE</promise>"; then
    echo "✅ All stories complete!"
    exit 0
  fi

  sleep 2
done

echo "⚠️ Max iterations reached without completion"
exit 1
```

**Make it executable:**
```bash
chmod +x scripts/ralph/ralph.sh
```

**Usage:**
```bash
./scripts/ralph/ralph.sh 25  # Run up to 25 iterations
```

### 2. prompt.md

```markdown
# Ralph Agent Instructions

You are Ralph, an autonomous coding agent. Work on ONE story at a time.

## Your Task (Each Iteration)

1. Read `scripts/ralph/prd.json` to see all user stories
2. Read `scripts/ralph/progress.txt` to learn from previous iterations
   - Check **Codebase Patterns** section first
3. Verify you're on the correct branch (from prd.json)
4. Pick the highest priority story where `passes: false`
5. Implement ONLY that ONE story
6. Run tests and typecheck:
   - `npm run typecheck` (or equivalent)
   - `npm test` (or pytest, go test, etc.)
7. If tests pass:
   - Commit with message: `feat: [STORY-ID] - [Story Title]`
   - Update prd.json: set `passes: true` for that story
   - Append learnings to progress.txt (see format below)
8. If tests fail:
   - Fix the issues
   - Try again
   - Log what you learned

## Progress Log Format

APPEND to `scripts/ralph/progress.txt`:

```
## [Date] - [Story ID]: [Title]
- **What was implemented:** Brief description
- **Files changed:** List of files
- **Learnings:**
  - Patterns discovered
  - Gotchas encountered
  - Dependencies found
---
```

## Codebase Patterns Section

At the TOP of progress.txt, maintain a "Codebase Patterns" section:

```
## Codebase Patterns
- When modifying X, also update Y
- Tests require Z to be running
- Use pattern A for feature B
```

Update this when you discover reusable patterns.

## Stop Condition

If ALL user stories have `passes: true`, reply ONLY:

```
<promise>COMPLETE</promise>
```

Otherwise, end your turn normally after implementing one story.

## Important Rules

- ONE story per iteration
- Always run tests before committing
- Keep stories small (fits in one context window)
- Learn from progress.txt
- Commit only when tests pass
- Be explicit in learnings
```

### 3. prd.json

```json
{
  "branchName": "ralph/feature-name",
  "userStories": [
    {
      "id": "US-001",
      "title": "Descriptive title",
      "acceptanceCriteria": [
        "Specific requirement 1",
        "Specific requirement 2",
        "Tests pass",
        "Typecheck passes"
      ],
      "priority": 1,
      "passes": false,
      "notes": "Optional context or constraints"
    },
    {
      "id": "US-002",
      "title": "Next feature",
      "acceptanceCriteria": [
        "Clear, testable criteria",
        "Builds on US-001"
      ],
      "priority": 2,
      "passes": false,
      "notes": ""
    }
  ]
}
```

**Important:**
- `branchName` - Git branch to work on
- `priority` - Lower number = done first
- `passes` - Set to `true` when story is complete
- Keep stories SMALL (one context window each)

### 4. progress.txt

```markdown
# Ralph Progress Log
Started: [Date]
Project: [Project Name]

## Codebase Patterns
(Ralph will populate patterns here as it learns)

## Key Files
(Ralph will document important files here)

---
(Ralph appends learnings after each story below)
```

## Writing Good User Stories

### ❌ Too Vague:
```json
{
  "title": "Add authentication",
  "acceptanceCriteria": ["Users can log in"]
}
```

### ✅ Clear and Explicit:
```json
{
  "title": "Add login form component",
  "acceptanceCriteria": [
    "Form has email and password fields",
    "Email field validates format",
    "Shows error message on invalid input",
    "Submits to /api/login endpoint",
    "Tests pass for validation logic",
    "Component renders at /login route"
  ]
}
```

### ❌ Too Big:
```json
{
  "title": "Build entire authentication system"
}
```

### ✅ Right Size (break into multiple stories):
```json
[
  {"id": "US-001", "title": "Add login form UI"},
  {"id": "US-002", "title": "Add login API endpoint"},
  {"id": "US-003", "title": "Add session management"},
  {"id": "US-004", "title": "Add logout functionality"}
]
```

## Best Practices

1. **Start Small**: 3-5 stories for your first Ralph loop
2. **Clear Criteria**: Every story needs testable acceptance criteria
3. **Fast Feedback**: Must have automated tests (unit tests, typecheck, linters)
4. **One Story = One Commit**: Keep commits focused
5. **Review Everything**: Ralph is autonomous but you still review/merge
6. **Learn from Failures**: If Ralph gets stuck, improve the story criteria
7. **Compound Learning**: Later stories benefit from earlier learnings

## Quick Start Guide

### Step 1: Create the Structure
```bash
mkdir -p scripts/ralph
cd scripts/ralph
```

### Step 2: Create Files
1. Create `ralph.sh` (use template above)
2. Create `prompt.md` (use template above)
3. Create `prd.json` with your user stories
4. Create empty `progress.txt` with header

### Step 3: Prepare Your Project
```bash
# Make sure you have tests
npm test  # or pytest, go test, etc.

# Make sure typecheck works
npm run typecheck  # or tsc, mypy, etc.

# Create the feature branch
git checkout -b ralph/your-feature
```

### Step 4: Run Ralph
```bash
chmod +x scripts/ralph/ralph.sh
./scripts/ralph/ralph.sh 20  # Run up to 20 iterations
```

### Step 5: Monitor Progress
```bash
# Check story status
cat scripts/ralph/prd.json | jq '.userStories[] | {id, passes}'

# Read learnings
cat scripts/ralph/progress.txt

# See commits
git log --oneline -10
```

### Step 6: Review and Merge
```bash
# Review all changes
git diff main

# Run tests yourself
npm test && npm run typecheck

# Merge when satisfied
git checkout main
git merge ralph/your-feature
```

## Monitoring a Running Ralph Loop

While Ralph is running, you can:

```bash
# Watch git commits in real-time
watch -n 5 'git log --oneline -5'

# Monitor progress file
tail -f scripts/ralph/progress.txt

# Check JSON status
watch -n 10 'cat scripts/ralph/prd.json | jq ".userStories[] | {id, title, passes}"'
```

## Troubleshooting

### Ralph Gets Stuck on One Story
- Story criteria might be too vague
- Tests might be flaky
- Check progress.txt for errors
- Manually fix and let Ralph continue

### Ralph Completes Too Fast Without Actually Working
- Acceptance criteria not specific enough
- Missing test validation
- Add more explicit criteria

### Tests Keep Failing
- Story might be too complex
- Break into smaller stories
- Check if dependencies are correct

### Ralph Changes Wrong Files
- Criteria too broad
- Add constraints: "Only modify files in src/components/"
- Be explicit about scope

## Example Ralph Loop Projects

### Example 1: CLI Tool
```json
{
  "branchName": "ralph/cli-tool",
  "userStories": [
    {
      "id": "US-001",
      "title": "Add argument parser",
      "acceptanceCriteria": [
        "Accepts --input and --output flags",
        "Shows help with --help",
        "Tests pass"
      ]
    },
    {
      "id": "US-002",
      "title": "Add file reading function",
      "acceptanceCriteria": [
        "Reads file from --input path",
        "Handles file not found error",
        "Returns file contents",
        "Unit tests pass"
      ]
    }
  ]
}
```

### Example 2: Web Feature
```json
{
  "branchName": "ralph/search-feature",
  "userStories": [
    {
      "id": "US-001",
      "title": "Add search input component",
      "acceptanceCriteria": [
        "Input field with placeholder",
        "Debounces input (500ms)",
        "Emits onChange event",
        "Component tests pass"
      ]
    },
    {
      "id": "US-002",
      "title": "Add search API endpoint",
      "acceptanceCriteria": [
        "GET /api/search?q=query",
        "Returns JSON array of results",
        "Handles empty query",
        "API tests pass"
      ]
    }
  ]
}
```

## Tips for Security/Pentesting Projects

Since you work in security/pentesting:

⚠️ **Special Considerations:**
- Always review Ralph's code before running it
- Don't use Ralph for client/production pentesting
- Perfect for personal tools and CTF practice
- Add security checks to acceptance criteria:
  - "No hardcoded credentials"
  - "Validates all user input"
  - "Doesn't execute arbitrary commands"

**Good Ralph Projects for Pentesting:**
- Enumeration script wrappers
- Report generators
- Log parsers
- CTF toolkit utilities
- Practice exploit development
- Automation scripts for HTB/TryHackMe

**Bad Ralph Projects for Pentesting:**
- Actual client engagement tools
- Security-critical components
- Exploit chains (too complex/sensitive)

## Ready to Build?

When you're ready to create a Ralph loop, provide:
1. **Project description**: What are you building?
2. **Language/framework**: Python, Go, Node.js, etc.
3. **Test setup**: What test command? (pytest, npm test, go test)
4. **Feature goal**: What should the end result do?

The AI will help you:
- Break it into user stories
- Create the file structure
- Write initial tests
- Set up the Ralph loop
- Monitor progress

---

## Reference: Original Ralph Loop Article

Key points from the Ralph loop concept:
- Autonomous coding while you sleep
- Fresh context window each iteration
- Memory through git + text files
- Learns patterns as it goes
- 13 stories ~= 15 iterations ~= 1 hour
- By story 10, Ralph knows your patterns

**Remember:** Ralph is a tool, not magic. You still:
- Define the stories
- Review the code
- Merge when satisfied
- Learn from watching it work
