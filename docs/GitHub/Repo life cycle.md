[Git cheet sheet]([[https]]://www.atlassian.com/git/tutorials/atlassian-git-cheatsheet)
[Setting up a new repo]([[https]]://gist.github.com/alexpchin/dc91e723d4db5018fef8)
[[[https]]://www.atlassian.com/git]([[https]]://www.atlassian.com/git)
from within the folder you want to make a repo
## Create a new repository on the command line 
```bash
touch README.md
git init
git add README.md
git commit -m "first commit"
git remote add origin git@github.com:alexpchin/<reponame>.git
git push -u origin master
```
## Push an existing repository from the command line
```bash
git remote add origin git@github.com:alexpchin/<reponame>.git
git push -u origin master
```
View items to commit
```bash
git status
```
# Workflow
1. checkout with branch name/what you are doing
	1. branch name can be a short description of what is being worked on
	2. without the -b git looks for an existing 
	```bash
	git checkout -b 'branch name'
	```
 1. Make changes to my file 
	 1. git status will make file text red in git status - not ready to commit
	 
 3. Verify the files I want to push to github with "git status" from within file
	```bash 
	 git status
	```
 4. git add 'path where the files live' 
	 1. git status will turn text green - ready to commit 
	```bash
	 git add 'filename'
	```
 5. git commit -m 'comment on the commit' for short messages
	 1. git commit - alone will give you an editor for more verbose messges
	 2. This will clear the working tree
	```bash
	git commit -m "updated README"
	```
6. git log will show commits before pushing
	```bash
	git log
	```
 7. Push changes to Github 
	 1. will generate a link in shell to GitHub
	 2. this will push the change to github
	 3. enter notes and click create pull request
	```bash
	git push -u origin HEAD
	```
8. check 'files changed' tab to view changes before merging PR
9. click Merge pull request
10. click Confirm Merge
11. Checkout the master branch
	```bash
	git checkout master
	```
12. git pull to the latest master branch from GitHub
	```bash
	git pull
	```