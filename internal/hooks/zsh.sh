# pentrail zsh shell-integration hook.
# Sourced into the interactive shell that pentrail starts. zsh gives us real
# preexec/precmd hooks and hands preexec the full command line, so segmentation
# here is more reliable than under bash.

# Markers carry $PENTRAIL_TOKEN so output from a scanned target cannot forge
# them. Without a token (not launched by pentrail) the hook does nothing.
if [ -n "$PENTRAIL" ] && [ -n "$PENTRAIL_TOKEN" ] && [ -z "$__PENTRAIL_HOOKED" ]; then
  __PENTRAIL_HOOKED=1
  __PT="$PENTRAIL_TOKEN"

  __pentrail_osc() { printf '\033]697;%s;%s\007' "$__PT" "$1"; }

  __pentrail_preexec() {
    __pentrail_osc "CWD;$PWD"
    __pentrail_osc "CMD;$(printf '%s' "$1" | base64 | tr -d '\n')"
    __pentrail_osc "C"
  }

  __pentrail_precmd() {
    local ec=$?
    __pentrail_osc "D;$ec"
    __pentrail_osc "A"
  }

  autoload -Uz add-zsh-hook 2>/dev/null
  if whence add-zsh-hook >/dev/null 2>&1; then
    add-zsh-hook preexec __pentrail_preexec
    add-zsh-hook precmd __pentrail_precmd
  else
    preexec_functions+=(__pentrail_preexec)
    precmd_functions+=(__pentrail_precmd)
  fi

  # Transparently add a structured-output flag to recognised tools, save the
  # file under $PENTRAIL_ARTIFACTS, and announce it so `pentrail parse` can read
  # it. If the user already asked for structured output, we don't interfere.
  __pentrail_wrap() {
    local tool=$1; shift
    if [ -n "$PENTRAIL_BIN" ] && ! command "$PENTRAIL_BIN" __artifact-check >/dev/null 2>&1; then command "$tool" "$@"; return $?; fi
    if [ -z "$PENTRAIL_ARTIFACTS" ]; then command "$tool" "$@"; return $?; fi
    case " $* " in
      *" -oX "*|*" -oA "*|*" -of "*|*" -jsonl "*|*" -o "*) command "$tool" "$@"; return $?;;
    esac
    local path="$PENTRAIL_ARTIFACTS/${tool}-$(date +%s)-$$-${RANDOM}"
    case "$tool" in
      nmap)   path="$path.xml";   set -- "$@" -oX "$path";;
      ffuf)   path="$path.json";  set -- "$@" -o "$path" -of json;;
      nuclei) path="$path.jsonl"; set -- "$@" -jsonl -o "$path";;
      *)      command "$tool" "$@"; return $?;;
    esac
    __pentrail_osc "ART;$tool;$path"
    command "$tool" "$@"
    local __rc=$?
    __pentrail_osc "FIN;$path"   # the tool has finished writing $path
    return $__rc
  }
  nmap()   { __pentrail_wrap nmap "$@"; }
  ffuf()   { __pentrail_wrap ffuf "$@"; }
  nuclei() { __pentrail_wrap nuclei "$@"; }
fi
