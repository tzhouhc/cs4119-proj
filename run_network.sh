#!/bin/bash
# tmux-splitter.sh - Creates three splits in the current pane,
# runs commands, and closes them when done

# Check if we're in tmux
if [ -z "$TMUX" ]; then
  echo "Error: This script must be run inside a tmux session."
  exit 1
fi

# Get the current pane ID
CURRENT_PANE=$(tmux display-message -p "#{pane_id}")

# Function to split and run a command
split_and_run() {
  local split_type=$1  # "h" for horizontal, "v" for vertical
  local command=$2

  # Create a new split
  tmux split-window -v -l 10 -t "$CURRENT_PANE" "${1}"

  # Get the new pane ID
  local new_pane=$(tmux display-message -p "#{pane_id}")
}

# initial tracker
split_and_run "python3 main.py 0.0.0.0 50000 0.0.0.0 50000 $@"
sleep 0.1
split_and_run "python3 main.py 0.0.0.0 50001 0.0.0.0 50000 $@"
split_and_run "python3 main.py 0.0.0.0 50002 0.0.0.0 50000 $@"
split_and_run "python3 main.py 0.0.0.0 50003 0.0.0.0 50000 $@"

# Return focus to the original pane
tmux select-pane -t "$CURRENT_PANE"
