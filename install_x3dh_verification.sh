#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${X3DH_VERIFY_CONFIG:-$SCRIPT_DIR/.x3dh_verify.env}"

default_hax_root() {
  if [[ -n "${HAX_ROOT:-}" && -d "${HAX_ROOT:-}" ]]; then
    cd "$HAX_ROOT" 2>/dev/null && pwd || true
    return
  fi

  echo ""
}

write_config() {
  local hax_root="$1"
  local extraction_dir="$2"
  local venv_path="$3"
  local fstar_bin="$4"
  local opam_switch="$5"
  local load_opam_env="$6"
  local load_venv="$7"

  cat >"$CONFIG_FILE" <<EOF
# Local configuration for verified_x3dh F* extraction and verification.
HAX_ROOT="$hax_root"
EXTRACTION_DIR="$extraction_dir"
VENV_PATH="$venv_path"
FSTAR_BIN="$fstar_bin"
OPAM_SWITCH="$opam_switch"
LOAD_OPAM_ENV="$load_opam_env"
LOAD_VENV="$load_venv"
EOF

  echo "Wrote $CONFIG_FILE"
}

canonicalize_dir() {
  local path="$1"
  cd "$path" 2>/dev/null && pwd
}

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
  fi

  HAX_ROOT="${HAX_ROOT:-$(default_hax_root)}"
  EXTRACTION_DIR="${EXTRACTION_DIR:-$SCRIPT_DIR/proofs/fstar/extraction}"
  VENV_PATH="${VENV_PATH:-$SCRIPT_DIR/../venv}"
  FSTAR_BIN="${FSTAR_BIN:-fstar.exe}"
  OPAM_SWITCH="${OPAM_SWITCH:-}"
  LOAD_OPAM_ENV="${LOAD_OPAM_ENV:-1}"
  LOAD_VENV="${LOAD_VENV:-1}"
}

run_opam_env() {
  if [[ "$LOAD_OPAM_ENV" != "1" ]]; then
    echo "  skipped: opam env loading disabled"
    return 0
  fi

  if ! command -v opam >/dev/null 2>&1; then
    echo "  missing: opam"
    return 1
  fi

  echo "  ok: opam"

  if [[ -n "$OPAM_SWITCH" ]]; then
    if eval "$(opam env --switch "$OPAM_SWITCH" --set-switch)"; then
      echo "  ok: opam switch $OPAM_SWITCH"
    else
      echo "  missing: opam switch $OPAM_SWITCH"
      return 1
    fi
  else
    if eval "$(opam env)"; then
      echo "  ok: opam env"
    else
      echo "  missing: opam env"
      return 1
    fi
  fi
}

check_prereqs() {
  load_config

  local failed=0

  echo "Checking prerequisites"

  if ! command -v cargo >/dev/null 2>&1; then
    echo "  missing: cargo"
    failed=1
  else
    echo "  ok: cargo"
  fi

  if cargo hax --version >/dev/null 2>&1; then
    echo "  ok: cargo hax"
  else
    echo "  missing: cargo hax"
    failed=1
  fi

  if [[ -z "$HAX_ROOT" || ! -d "$HAX_ROOT" ]]; then
    echo "  missing: HAX_ROOT directory"
    failed=1
  else
    echo "  ok: HAX_ROOT=$HAX_ROOT"
  fi

  if [[ -d "$HAX_ROOT/proof-libs/fstar/core" ]]; then
    echo "  ok: hax F* proof libs"
  else
    echo "  missing: $HAX_ROOT/proof-libs/fstar/core"
    failed=1
  fi

  if [[ -d "$HAX_ROOT/proof-libs/fstar/rust_primitives" ]]; then
    echo "  ok: hax F* rust primitives"
  else
    echo "  missing: $HAX_ROOT/proof-libs/fstar/rust_primitives"
    failed=1
  fi

  if [[ -d "$HAX_ROOT/hax-lib/proofs/fstar/extraction" ]]; then
    echo "  ok: hax-lib F* extraction support"
  else
    echo "  missing: $HAX_ROOT/hax-lib/proofs/fstar/extraction"
    failed=1
  fi

  if run_opam_env; then
    :
  else
    failed=1
  fi

  if command -v "$FSTAR_BIN" >/dev/null 2>&1; then
    echo "  ok: $FSTAR_BIN"
  else
    echo "  missing: $FSTAR_BIN"
    failed=1
  fi

  if command -v make >/dev/null 2>&1; then
    echo "  ok: make"
  else
    echo "  warning: make not found (needed for verify-make-lax / verify-make / verify-make-all)"
  fi

  if [[ $failed -ne 0 ]]; then
    echo
    echo "Prerequisite check failed."
    return 1
  fi

  echo
  echo "All prerequisite checks passed."
}

setup_repo() {
  load_config
  mkdir -p "$EXTRACTION_DIR"
  echo "Ensured extraction directory: $EXTRACTION_DIR"
}

install_local() {
  check_prereqs
  setup_repo
  echo "Running local crate build/tests"
  (
    cd "$SCRIPT_DIR"
    cargo test
  )
}

run_verifier() {
  local mode="${1:-all}"
  local verify_mode="${2:-verify-all}"
  local partial_arg="${3:-}"

  if [[ "$mode" == "partial" ]]; then
    "$SCRIPT_DIR/verify_x3dh" "$mode" "$verify_mode" "$partial_arg"
  else
    "$SCRIPT_DIR/verify_x3dh" "$mode" "$verify_mode"
  fi
}

show_help() {
  cat <<EOF
Usage:
  ./install_x3dh_verification.sh <command> [options]

Commands:
  configure
  check
  setup
  install
  run [mode] [verification-mode]
  all [mode] [verification-mode]
  verify-make-lax
  verify-make
  verify-make-all
  help

configure options:
  --hax-root PATH
  --extraction-dir PATH
  --venv PATH
  --fstar-bin CMD
  --opam-switch NAME
  --no-opam-env
  --no-venv

Examples:
  ./install_x3dh_verification.sh configure --hax-root /absolute/path/to/hax
  ./install_x3dh_verification.sh check
  ./install_x3dh_verification.sh install
  ./install_x3dh_verification.sh run all verify-all
  ./install_x3dh_verification.sh run all verify-make-all
  ./install_x3dh_verification.sh verify-make-lax
  ./install_x3dh_verification.sh all kdf verify-kdf
EOF
}

configure_cmd() {
  local hax_root="${HAX_ROOT:-}"
  local extraction_dir="$SCRIPT_DIR/proofs/fstar/extraction"
  local venv_path="$SCRIPT_DIR/../venv"
  local fstar_bin="fstar.exe"
  local opam_switch=""
  local load_opam_env="1"
  local load_venv="1"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --hax-root)
        hax_root="$2"
        shift 2
        ;;
      --extraction-dir)
        extraction_dir="$2"
        shift 2
        ;;
      --venv)
        venv_path="$2"
        shift 2
        ;;
      --fstar-bin)
        fstar_bin="$2"
        shift 2
        ;;
      --opam-switch)
        opam_switch="$2"
        shift 2
        ;;
      --no-opam-env)
        load_opam_env="0"
        shift
        ;;
      --no-venv)
        load_venv="0"
        shift
        ;;
      *)
        echo "Unknown configure option: $1"
        return 1
        ;;
    esac
  done

  if [[ -z "$hax_root" ]]; then
    echo "Missing required hax root."
    echo "Use: ./install_x3dh_verification.sh configure --hax-root /path/to/hax"
    echo "Or export HAX_ROOT=/path/to/hax before running configure."
    return 1
  fi

  if ! hax_root="$(canonicalize_dir "$hax_root")"; then
    echo "Invalid hax root: $hax_root"
    return 1
  fi

  if ! mkdir -p "$(dirname "$extraction_dir")"; then
    echo "Failed to create extraction directory parent: $(dirname "$extraction_dir")"
    return 1
  fi

  extraction_dir="$(canonicalize_dir "$(dirname "$extraction_dir")")/$(basename "$extraction_dir")"
  if [[ "$load_venv" == "1" && -d "$venv_path" ]]; then
    venv_path="$(canonicalize_dir "$venv_path")"
  fi

  write_config "$hax_root" "$extraction_dir" "$venv_path" "$fstar_bin" "$opam_switch" "$load_opam_env" "$load_venv"
}

main() {
  local command="${1:-help}"
  shift || true

  case "$command" in
    configure)
      configure_cmd "$@"
      ;;
    check)
      check_prereqs
      ;;
    setup)
      setup_repo
      ;;
    install)
      install_local
      ;;
    run)
      run_verifier "${1:-all}" "${2:-verify-all}" "${3:-}"
      ;;
    all)
      install_local
      run_verifier "${1:-all}" "${2:-verify-all}" "${3:-}"
      ;;
    verify-make-lax|verify-make|verify-make-all)
      run_verifier "verify-only" "$command"
      ;;
    help|"")
      show_help
      ;;
    *)
      echo "Unknown command: $command"
      show_help
      return 1
      ;;
  esac
}

main "$@"
