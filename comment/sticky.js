// Post or update the ONE sticky RuleHawk comment on a pull request.
//
// Shared by the gate action (action.yml) and the combining action
// (comment/action.yml), both of which call it from actions/github-script:
//
//   const sticky = require(process.env.RH_STICKY_JS);
//   await sticky({github, context, core, bodyPath, issueNumber});
//
// The comment is found by its hidden marker among comments the workflow's
// GITHUB_TOKEN wrote (both actions always post with it, as
// github-actions[bot]). A person or another bot quoting the marker must not
// capture the verdict: GitHub would refuse the update, or another account's
// comment would carry it, and RuleHawk's own comment would keep the old one.
'use strict';

const fs = require('fs');

const MARKER = '<!-- rulehawk-gate -->';

const AUTHOR = 'github-actions[bot]';

module.exports = async function sticky({github, context, core, bodyPath, issueNumber,
                                        author = AUTHOR}) {
  let body;
  try {
    body = fs.readFileSync(bodyPath, 'utf8');
  } catch (e) {
    core.warning('no comment body: ' + e);
    return null;
  }
  const {owner, repo} = context.repo;
  // Every page: on a busy PR the verdict comment can sit past the first 100,
  // and missing it would post a second comment under a stale first one.
  const comments = await github.paginate(github.rest.issues.listComments,
    {owner, repo, issue_number: issueNumber, per_page: 100});
  const ours = (c) => Boolean(c && c.body && c.body.includes(MARKER) &&
    c.user && c.user.login === author);
  const mine = comments.find(ours);
  if (mine) {
    await github.rest.issues.updateComment({owner, repo, comment_id: mine.id, body});
    return mine.id;
  }
  const {data: made} = await github.rest.issues.createComment(
    {owner, repo, issue_number: issueNumber, body});
  return made.id;
};

module.exports.MARKER = MARKER;
