#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./.ci/publish-central.sh [bundle-name]
  ./.ci/publish-central.sh --no-wait [bundle-name]

Required env:
  CENTRAL_SONATYPE_TOKEN_USERNAME
  CENTRAL_SONATYPE_TOKEN_PASSWORD
  CENTRAL_SONATYPE_SIGNING_KEY
  CENTRAL_SONATYPE_SIGNING_PASSWORD

What it does:
  1) Builds signed Maven artifacts into build/central-bundle-repo/ using Gradle
     - :ethree-common:publishMavenJavaPublicationToCentralBundleRepository
     - :ethree-kotlin:publishMavenJavaPublicationToCentralBundleRepository
     - :ethree-enclave:publishMavenJavaPublicationToCentralBundleRepository
  2) Removes repository/module metadata not accepted by Central bundle upload
  3) Generates .md5 and .sha1 for repository files (excluding *.asc/*.md5/*.sha1)
  4) Creates build/central-bundle.zip
  5) Uploads the bundle to Sonatype Central Portal (publishingType=AUTOMATIC)
  6) Waits for Central Portal to finish publishing (unless --no-wait)

Optional env:
  CENTRAL_POLL_ATTEMPTS (default: 60)
  CENTRAL_POLL_INTERVAL_SEC (default: 30)
EOF
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: Missing required env var: ${name}" >&2
    exit 1
  fi
}

md5_file() {
  local file="$1"
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$file" | awk '{print $1}'
  else
    # macOS
    md5 -q "$file"
  fi
}

sha1_file() {
  local file="$1"
  if command -v sha1sum >/dev/null 2>&1; then
    sha1sum "$file" | awk '{print $1}'
  else
    # macOS
    shasum -a 1 "$file" | awk '{print $1}'
  fi
}

json_get_state() {
  local json="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$json"
import json,sys
try:
    data = json.loads(sys.argv[1])
    print(data.get("deploymentState",""))
except Exception:
    print("")
PY
    return 0
  fi

  # Best-effort fallback without python3.
  echo "$json" | sed -nE 's/.*"deploymentState"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n 1
}

wait_for_published() {
  local bearer="$1"
  local deployment_id="$2"
  local attempts="${CENTRAL_POLL_ATTEMPTS:-60}"
  local interval="${CENTRAL_POLL_INTERVAL_SEC:-30}"

  echo "Waiting for Central Portal publish (attempts=${attempts}, interval=${interval}s)..."

  for i in $(seq 1 "$attempts"); do
    local status_json
    status_json="$(
      curl -sS --fail --request POST \
        --header "Authorization: Bearer ${bearer}" \
        "https://central.sonatype.com/api/v1/publisher/status?id=${deployment_id}"
    )"

    local state
    state="$(json_get_state "$status_json")"
    echo "Central state: ${state:-<unknown>} (attempt ${i}/${attempts})"

    if [[ "$state" == "PUBLISHED" ]]; then
      return 0
    fi
    if [[ "$state" == "FAILED" ]]; then
      echo "Central deployment FAILED" >&2
      echo "$status_json" >&2
      return 1
    fi

    sleep "$interval"
  done

  echo "Timed out waiting for Central Portal publish (deployment_id=${deployment_id})" >&2
  return 1
}

main() {
  local wait="true"
  if [[ "${1:-}" == "--no-wait" ]]; then
    wait="false"
    shift
  fi
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_env CENTRAL_SONATYPE_TOKEN_USERNAME
  require_env CENTRAL_SONATYPE_TOKEN_PASSWORD
  require_env CENTRAL_SONATYPE_SIGNING_KEY
  require_env CENTRAL_SONATYPE_SIGNING_PASSWORD

  local name="${1:-}"
  if [[ -z "$name" ]]; then
    if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
      name="local-$(git rev-parse --short HEAD)"
    else
      name="local-$(date +%Y%m%d-%H%M%S)"
    fi
  fi

  # Map to the Gradle props expected by signing blocks in build scripts.
  export ORG_GRADLE_PROJECT_signingKey="${CENTRAL_SONATYPE_SIGNING_KEY}"
  export ORG_GRADLE_PROJECT_signingPassword="${CENTRAL_SONATYPE_SIGNING_PASSWORD}"

  rm -rf build/central-bundle-repo build/central-bundle.zip

  ./gradlew :ethree-common:publishMavenJavaPublicationToCentralBundleRepository :ethree-kotlin:publishMavenJavaPublicationToCentralBundleRepository :ethree-enclave:publishMavenJavaPublicationToCentralBundleRepository --no-daemon --stacktrace

  if [[ ! -d build/central-bundle-repo ]]; then
    echo "ERROR: build/central-bundle-repo was not created" >&2
    exit 1
  fi

  # Central bundle should not include repository metadata/module metadata.
  find build/central-bundle-repo -type f -name 'maven-metadata.xml*' -delete || true
  find build/central-bundle-repo -type f -name '*.module*' -delete || true

  while IFS= read -r -d '' file; do
    md5_file "$file" > "${file}.md5"
    sha1_file "$file" > "${file}.sha1"
  done < <(find build/central-bundle-repo -type f \
    ! -name '*.asc' \
    ! -name '*.md5' \
    ! -name '*.sha1' \
    -print0)

  (cd build/central-bundle-repo && zip -q -r ../central-bundle.zip .)

  if [[ ! -f build/central-bundle.zip ]]; then
    echo "ERROR: build/central-bundle.zip was not created" >&2
    exit 1
  fi

  local bearer
  bearer="$(printf "%s:%s" "${CENTRAL_SONATYPE_TOKEN_USERNAME}" "${CENTRAL_SONATYPE_TOKEN_PASSWORD}" | base64 | tr -d '\n')"

  echo "Uploading build/central-bundle.zip as '${name}'..."
  local deployment_id
  deployment_id="$(
    curl -sS --fail \
      --header "Authorization: Bearer ${bearer}" \
      --form "bundle=@build/central-bundle.zip" \
      "https://central.sonatype.com/api/v1/publisher/upload?publishingType=AUTOMATIC&name=${name}"
  )"

  if [[ -z "${deployment_id}" ]]; then
    echo "ERROR: Central Portal did not return deployment ID" >&2
    exit 1
  fi

  echo "Central deployment id: ${deployment_id}"

  if [[ "$wait" == "true" ]]; then
    wait_for_published "$bearer" "$deployment_id"
  fi

  echo "Done."
}

main "$@"
