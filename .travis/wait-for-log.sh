#!/bin/sh
# Keep the job open until Travis has archived this job's log through the runner's final
# result line, so a harvest made right after the job finishes sees the complete test output.
# Runs in after_script, which cannot change the build result.
leg="${1:-job}"
cap="${2:-900}"
url="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
waited=0
while [ "$waited" -lt "$cap" ]; do
  if curl -fsSL "$url" 2>/dev/null | grep -Eq 'BUILD (SUCCESSFUL|FAILED) in [0-9]'; then
    echo "wait-for-log ($leg): archived log complete after ${waited}s"
    exit 0
  fi
  echo "wait-for-log ($leg): waiting... (${waited}s)"
  sleep 20
  waited=$((waited + 20))
done
echo "wait-for-log ($leg): stopped waiting after ${cap}s"
exit 0
