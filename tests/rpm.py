#!/usr/bin/python3

# fake "rpm" command to allow testing of package coupling in permctl in the
# fake test root environment.

import sys

args = sys.argv[1:]

if len(args) != 4:
    raise Exception("fake 'rpm' only supports 'rpm -qf /path --queryformat %{NAME} ")
elif args[0] != "-qf" or args[2] != "--queryformat" or args[3] != "%{NAME} ":
    raise Exception("fake 'rpm' only supports -qf")

query_path = args[1]

found_match = False

try:
    with open("/var/lib/rpm/Packages.db") as db:
        for line in db.readlines():
            pkg, path = line.split()
            if path == query_path:
                print(f"{pkg} ", end='')
                found_match = True
except FileNotFoundError:
    pass

if not found_match:
    print(f"file {query_path} is not owned by any package")
    sys.exit(1)
