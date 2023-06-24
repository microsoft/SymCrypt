# Branches
This file describes the branch structure used for SymCrypt.

## Branch Names
- **main**: The latest fully validated Symcrypt library.
- **publish**:	This branch gets published to the public GitHub repo as the main branch there. This branch should only be used for publishing, and not for anything else.
- **user/<alias>/\***: Working branch names for each contributor.
- **CONF-\***:	Branch names for temporarily confidential changes. One CONF-* branch per change.
- **CONF**:	Branch that combines main and all the CONF-* branches for testing. Only exists when there are multiple confidential changes.

## Work flow for normal feature work
1. Create a user/<alias>/\* branch off main for the work
1. Do the development work on that branch
1. Locally build and test the private changes (use build.py or scBuild)
1. Use a PR to merge the change into main

## Work flow for confidential changes
1. Create a CONF-* branch off main
1. Develop the fix inside that branch (or use sub-branches for more complex changes)
1. **DO NOT** merge this into main
1. For testing, merge the change into the CONF branch, and build out of that branch. (If only one CONF-* branch is active, you can use that to build and test.)
1. When the change is no longer confidential, use a PR to merge the change into main and delete the CONF-* branch.

To keep the CONF-* branches current they have to be rebased to the top of main at suitable intervals.

The CONF branch should be rebuilt at regular intervals to keep it in sync with main by:
- rebase all CONF-* branches to the top of main
- Delete the CONF branch and re-create it from the top of main
- merge all CONF-* branches into CONF

Confidential changes should be relatively rare, so much of the time we won't even 
have a CONF branch, and multiple CONF-* branches should be very rare.
However, this structure allows us to add new confidential 
changes and later publish each confidential change without any restriction to order. 

Note: the reason for having confidential changes is that a fix for a security 
weakness cannot be published until the patch is available and deployed for all
downlevel platforms. As soon as the fix is deployed, the confidential change
must be merged into main so that it can be published.

## Work flow for publishing
The publish branch only ever takes merges from main, and never from anywhere
else. The publishing workflow is:

1. Merge main into publish 
1. Use `PublishToGithub.cmd` to push the publish branch to Github






