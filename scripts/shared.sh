#!/usr/bin/env bash

get_tmux_option() {
	local option=$1
	local default_value=$2
	local option_value=$(tmux show-option -gqv "$option")
	if [ -z "$option_value" ]; then
		echo "$default_value"
	else
		echo "$option_value"
	fi
}

set_tmux_option() {
	local option=$1
	local value=$2
	tmux set-option -gq "$option" "$value"
}

parse_ssh_port() {
  # If there is a port get it
  local port=$(echo $1|grep -Eo '\-p\s*([0-9]+)'|sed 's/-p\s*//')

  if [ -z $port ]; then
    local port=22
  fi

  echo $port
}

get_ssh_user() {
  local ssh_user=$(whoami)

  for ssh_config in `awk '
    $1 == "Host" {
      gsub("\\\\.", "\\\\.", $2);
      gsub("\\\\*", ".*", $2);
      host = $2;
      next;
    }
    $1 == "User" {
      $1 = "";
      sub( /^[[:space:]]*/, "" );
      printf "%s|%s\n", host, $0;
    }' .ssh/config`; do
    local host_regex=${ssh_config%|*}
    local host_user=${ssh_config#*|}
    if [[ "$1" =~ $host_regex ]]; then
      ssh_user=$host_user
      break
    fi
  done

  echo $ssh_user
}

get_ssh_command() {
  local pid="$1"
  local cmd
  until [ -z "$pid" ] || cmd="$(ps -o command -p "$pid" | xargs -I{} echo {} | grep ssh)"; do
    pid="$(pgrep -P "$pid")"
    cmd=''
  done
  echo "$cmd"
}

get_pid_command() {
  # todo: get recursive
  local command=$1

  # First get the current pane command pid to get the full command with arguments
  local pid=$(tmux display-message -p "#{pane_pid}")
  local cmd1=$(pgrep -flaP $pid)

  #echo "get_pid_command: [$pid] [$cmd1] [$cmd2]"
}

get_cmd_recursive() {
    local pid=$(tmux display-message -p '#{pane_pid}')
    local cmd=$(tmux display-message -p '#{pane_current_command}')

    # Docker/ssh was called directly
    if [[ $cmd = "docker" ]] || [[ $cmd = "ssh" ]] || [[ $cmd = "sshpass" ]]; then
        local cmd=$(pgrep -flaP $pid)
        local pid=$(echo $cmd | cut -d' ' -f1)
        echo "${cmd//$pid }"
        return
    fi

    # Recursively search for last command running
    local depth=0
    while [ -n "$pid" ] && [ "$depth" -lt "5" ]; do
        local prevcmd=${cmd//$pid }
        local cmd=$(pgrep -flaP $pid | tail -n1)
        local pid=$(echo $cmd | cut -d' ' -f1)
        ((++depth))
    done

    # return command
    echo "$prevcmd"
}

get_remote_info2() {
  local command=$1

  # First get the current pane command pid to get the full command with arguments
  local cmd=$(get_cmd_recursive $command)

  local port=$(parse_ssh_port "$cmd")

  local cmd=$(echo $cmd|sed 's/\-p\s*'"$port"'.*//g')
  local user=$(echo $cmd | awk '{print $NF}'|cut -f1 -d@)
  local host=$(echo $cmd | awk '{print $NF}'|cut -f2 -d@)

  if [ $user == $host ]; then
    local user=$(get_ssh_user $host)
  fi

  case "$1" in
    "whoami")
      echo $user
      ;;
    "hostname")
      echo $host
      ;;
    "port")
      echo $port
      ;;
    *)
      echo "$user@$host:$port"
      ;;
  esac
}

get_remote_info() {
  local command=$1

  # First get the current pane command pid to get the full command with arguments
  local pane_pid="$(tmux display-message -p "#{pane_pid}")"

  local cmd=$(get_ssh_command "$pane_pid" | sed -E 's/^[0-9]*[[:blank:]]*[a-z/]*ssh //')

  local port=$(parse_ssh_port "$cmd")

  local cmd=$(echo $cmd | sed 's/\-p\s*'"$port"'//g;s/.* \([^\s]*\) --.*/\1/')
  local user=$(echo $cmd | awk '{print $NF}' | cut -f1 -d@)
  local host=$(echo $cmd | awk '{print $NF}' | cut -f2 -d@)

  if [ $user == $host ]; then
    local user=$(get_ssh_user $host)
  fi

  case "$1" in
    "whoami")
      echo $user
      ;;
    "hostname")
      echo $host
      ;;
    "port")
      echo $port
      ;;
    *)
      echo "$user@$host:$port"
      ;;
  esac
}

get_info() {
  # If command is ssh do some magic
  if ssh_connected; then
    echo $(get_remote_info2 $1)
  else
    echo $($1)
  fi
}

ssh_connected() {
  # Get current pane command
  local cmd=$(get_cmd_recursive $command)
  # sshpass ssh $(which ssh) $(which sshpass)

  pattern="^ssh[[:blank:]].*|^sshpass[[:blank:]].*|^$(which ssh)[[:blank:]].*"
  exclude="SendEnv=GIT_PROTOCOL"
  [[ $cmd =~ $pattern ]] && [[ ! $cmd =~ $exclude ]]
}
