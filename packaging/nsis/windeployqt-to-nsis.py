#!/bin/env python3

# windeployqt-to-nsh
#
# Windeployqt-to-nsh - Convert the output of windeployqt to an equivalent set of
# NSIS "File" function calls.
#
# Rewritten in python from windeployqt-to-nsis.ps1, that has the following copyright:
#
# Copyright 2014 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import os
import subprocess

EXECUTABLE = sys.argv[1]
OUTFILE = sys.argv[2]

# Qt version
qmake_out = subprocess.run("qmake6 -query QT_VERSION", shell=True, check=True, capture_output=True, encoding="utf-8")
qt_version = qmake_out.stdout.strip()

# XXX The powershell script asserts that the Qt version is greater than 5.3. We already require Qt6 to build the
# installer using MSYS2 (currently not enforced).

# Windeploy output
windeploy_command = [
    "windeployqt6.exe",
    "--no-compiler-runtime",
    "--no-translations",
    "--list", "mapping",
    EXECUTABLE
]

out = subprocess.run(windeploy_command, shell=True, check=True, capture_output=True, encoding="utf-8")

with open(OUTFILE, 'w') as f:
    command_name = os.path.split(sys.argv[0])[1]
    header = """\
#
# Automatically generated by {}
#
# Qt version {}
#""".format(command_name, qt_version)

    print(header, file=f)

    current_dir = ""
    for line in out.stdout.splitlines():
        path, relative = line.split(" ")
        rel_path = os.path.split(relative)
        if len(rel_path) > 1:
            base_dir = rel_path[0].strip('"')
            if base_dir != current_dir:
                set_out_path = 'SetOutPath "$INSTDIR\{}"'.format(base_dir)
                print(set_out_path, file=f)
                current_dir = base_dir
        file_path = 'File {}'.format(path)
        print(file_path, file=f)

