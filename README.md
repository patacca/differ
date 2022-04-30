# differ
Simple binary diffing tool written in python and built on top of angr that uses the Weisfeiler-Lehman kernel graph to match similar functions.

# How it works
The tool is heavily inspired from the article [Weisfeiler-Lehman Graph Kernel for Binary Function Analysis](https://blog.quarkslab.com/weisfeiler-lehman-graph-kernel-for-binary-function-analysis.html).
It matches functions in two steps: first a heuristic based approach is used and then the Weisfeiler-Lehman graph kernel is used to match the remaining unmatched functions.

# How to use

## Set up the database

First of all you need to set up the database with `base-db.sql`

`>> sqlite3 db.sqlite3 < base-db.sql`

## Usage

Now you can run the program like this

`>> python differ.py prog1 prog2`
