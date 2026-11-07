# pentrail bash shell-integration hook.
# Sourced into the interactive shell that pentrail starts. It only emits escape
# markers so the capture layer can segment commands. Best-effort by design:
# if anything here breaks, you lose segmentation for a command, never the raw
# capture and never your shell.

# Markers carry $PENTRAIL_TOKEN so output from a scanned target cannot forge
# them. Without a token (not launched by pentrail) the hook does nothing.
if [ -n "$PENTRAIL" ] && [ -n "$PENTRAIL_TOKEN" ] && [ -z "$__PENTRAIL_HOOKED" ]; then
  __PENTRAIL_HOOKED=1
  __PT="$PENTRAIL_TOKEN"

  # Snapshot the last in-memory history entry. Never consult the history file.
  # The number proves freshness; settings that can omit the accepted line are
  # deliberately excluded below. This is not a reconstruction of typed bytes.
  __pentrail_history() {
    local HISTTIMEFORMAT= entry match_declared=
    local -a saved_match=("${BASH_REMATCH[@]}")
    declare -p BASH_REMATCH >/dev/null 2>&1 && match_declared=1
    entry=$(builtin history 1)
    __pentrail_history_number=
    __pentrail_history_text=
    if [[ $entry =~ ^[[:blank:]]*([0-9]+)[\ *][[:blank:]](.*)$ ]]; then
      __pentrail_history_number=${BASH_REMATCH[1]}
      __pentrail_history_text=${BASH_REMATCH[2]}
    fi
    # Regex captures belong to the user's shell too (e.g. a later command may
    # read BASH_REMATCH from its preceding [[ ... =~ ... ]] expression).
    if [[ -n $match_declared ]]; then
      BASH_REMATCH=("${saved_match[@]}")
    else
      unset BASH_REMATCH
    fi
  }

  __pentrail_prepare() {
    local ec=$?
    unset __pentrail_at_prompt
    __pentrail_history
    __pentrail_previous_history=${__pentrail_history_number:-0}
    return "$ec"
  }

  __pentrail_osc() { printf '\033]697;%s;%s\007' "$__PT" "$1"; }

  __pentrail_preexec() {
    local cmd=$1
    # With omitted/deduplicated history, custom readline callbacks or traps,
    # keep the existing simple-command fallback. A stale private history entry
    # must never be substituted for the command actually being executed.
    if [[ -o history && -z $HISTCONTROL && -z $HISTIGNORE ]] &&
       [[ -z $(bind -X 2>/dev/null) && -z $(trap -p) ]]; then
      __pentrail_history
      case "$__pentrail_previous_history:$__pentrail_history_number" in
        *[!0-9:]* | :* | *:) ;;
        *) if (( __pentrail_history_number == __pentrail_previous_history + 1 )); then
             cmd=$__pentrail_history_text
           fi ;;
      esac
    fi
    __pentrail_osc "CWD;$PWD"
    __pentrail_osc "CMD;$(printf '%s' "$cmd" | base64 | tr -d '\n')"
    __pentrail_osc "C"
  }

  __pentrail_precmd() {
    local ec=$?
    __pentrail_osc "D;$ec"
    __pentrail_osc "A"
    unset __pentrail_at_prompt
    return "$ec"
  }

  # DEBUG fires before every simple command; the at_prompt gate makes preexec
  # run once, for the first command entered after a prompt.
  __pentrail_debug() {
    [ -n "$COMP_LINE" ] && return
    [ -z "$__pentrail_at_prompt" ] && return
    case "$BASH_COMMAND" in
      __pentrail_precmd | __pentrail_debug) return ;;
    esac
    unset __pentrail_at_prompt
    __pentrail_preexec "$BASH_COMMAND"
  }

  # Preserve the user's DEBUG trap instead of replacing its behaviour.
  if [[ -z $(trap -p DEBUG) ]]; then
    trap '__pentrail_debug' DEBUG
    # PS0 runs after an accepted interactive input, before DEBUG. Prompt
    # callbacks are outside this phase and cannot become user-command records.
    declare -a __pentrail_phase_gate=()
    PS0="${PS0}"'${__pentrail_phase_gate[__pentrail_at_prompt=1]}'
    # Preserve scalar/array callbacks and their ordering; prep runs last so
    # prompt-time history imports cannot appear fresh on the next command.
    if [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == 'declare -a '* ]]; then
      PROMPT_COMMAND=(__pentrail_precmd "${PROMPT_COMMAND[@]}" __pentrail_prepare)
    elif [[ -n $PROMPT_COMMAND ]]; then
      # Keep a scalar callback as its own evaluation unit. Concatenating a
      # suffix would turn an existing trailing semicolon into invalid `;;`.
      PROMPT_COMMAND=(__pentrail_precmd "$PROMPT_COMMAND" __pentrail_prepare)
    else
      PROMPT_COMMAND=(__pentrail_precmd __pentrail_prepare)
    fi
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
