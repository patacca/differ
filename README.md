# differ
Simple binary diffing tool written in python and built on top of angr.

# How to use

## Set up the database

First of all you need to set up the database with `base-db.sql`

`>> sqlite3 db.sqlite3 < base-db.sql`

## Usage

Now you can run the program like this

`>> python differ.py prog1 prog2`
