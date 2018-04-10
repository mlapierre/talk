#!/usr/bin/env node

// ./tagversion.js <tag>
//
// - Will return 1 if the tag does not match the package.json version
// - Will return 0 if the tag matches the package.json version
// - Will return 0 if no tag is specified
const { version: packageVersion } = require('../package.json');
const tag = process.argv[2];
if (!tag) {
  return;
}

// All version identifiers should match the form:
//
// v<major>.<minor>.<patch>
//
const TAG_VERSION_PATTERN = /v([0-9]+.[0-9]+.[0-9]+)/;
const matches = TAG_VERSION_PATTERN.exec(tag);
if (!matches) {
  throw new Error(`tag: "${tag}" does not match expected pattern: "${TAG_VERSION_PATTERN}"`);
}

// Get the match from the regex match.
const tagVersion = matches[1];
if (!tagVersion || tagVersion !== packageVersion) {
  throw new Error(`tag: "${tagVersion}" does not match version in package.json: "${packageVersion}"`);
}
