if [ ! -d gdb ]; then
    echo "Oops! You don't appear to be in Babeltrace's tree's root!"
else
    gdbdir="$(pwd)/gdb"
    commandspath="$gdbdir/commands"
    cat << EOF > "$gdbdir/commands"
python
import sys
sys.path.insert(0, '$gdbdir/python')
end
source $gdbdir/python/inspect.py
source $gdbdir/cmds/resolve.gdb
alias bti = bt-inspect
EOF
    alias gdb="gdb -x \"$commandspath\""
    rehash 2>/dev/null
fi



