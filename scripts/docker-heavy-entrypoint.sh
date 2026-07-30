#!/bin/sh
set -e

if [ "$#" -eq 0 ]; then
    exec socket-basics -h
fi

case "$1" in
    socket-basics)
        shift
        exec socket-basics "$@"
        ;;
    socketcli)
        shift
        exec socketcli "$@"
        ;;
    *)
        exec socket-basics "$@"
        ;;
esac
