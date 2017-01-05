#!/bin/bash

echo "Updating current branch and submodules"
git pull && git submodule update --init --recursive
