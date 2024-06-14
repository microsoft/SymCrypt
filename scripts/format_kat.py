#!/usr/bin/env python3
"""
Helper script for reformatting known answer test (KAT) data files used by SymCrypt.
There's probably some magical Bash one-liner that could do this with sed, but I'm not a shell
wizard so I'm just going to use Python.
"""

import re
import sys

# Maximum length that lines are allowed to be. Lines will be split to this length if they exceed it,
# modulo the overrun tolerance below.
MAX_LINE_LENGTH = 100

# To avoid splitting lines that are just slightly longer than the maximum length, we allow a small
# tolerance.
OVERRUN_TOLERANCE = 10

def main():
    if len(sys.argv) != 2:
        print("Usage: format_kat.py <kat_file>")
        sys.exit(1)

    f = open(sys.argv[1], "r+")
    lines = f.readlines()

    modified_lines = []
    for line in lines:
        if "=" not in line or "\"" in line or len(line) <= (MAX_LINE_LENGTH + OVERRUN_TOLERANCE):
            modified_lines.append(line)
            continue

        # Fix extra whitespace before and after the '=' sign\
        line = re.sub(r"\s+=\s+", " = ", line)

        indent = line.index("=") + 2
        new_lines = []
        while len(line) > 0:
            is_data_start_line = "=" in line
            reserved = 1 if is_data_start_line else indent + 1

            # Our data values are hex strings (excluding string literals, which we ignore), so we
            # don't want to split a hex value in half. It wouldn't be a problem for the parser, but
            # it's aesthetically unpleasant and harder to read. So if the length of data on the line
            # would be odd, we reserve an extra character. `indent` points to the index of the first
            # hex character, so `(indent - 1)` is the length of the line up to that point; if this
            # is odd, it means the length of the remaining data on the line would also be odd.
            if (indent - 1) % 2 != 0:
                reserved += 1

            new_line = line[:MAX_LINE_LENGTH - reserved]
            if "\n" not in new_line:
                new_line += "\\\n"

            if not is_data_start_line:
                new_line = " " * indent + new_line

            line = line[MAX_LINE_LENGTH - reserved:]
            new_lines.append(new_line)

        modified_lines.extend(new_lines)

    # for line in modified_lines:
    #     print(line, end="")
    
    # print("") # Extra newline

    f.truncate(0)
    f.seek(0)
    f.writelines(modified_lines)
    f.close()

if __name__ == "__main__":
    main()

