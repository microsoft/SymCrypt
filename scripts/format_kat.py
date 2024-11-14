#!/usr/bin/env python3
"""
Helper script for reformatting known answer test (KAT) data files used by SymCrypt.
There's probably some magical Bash one-liner that could do this with sed, but I'm not a shell
wizard so I'm just going to use Python.
"""

import re
import sys

# Maximum length that lines are allowed to be
# Lines containing hex data will be split to this length or shorter s.t. each
# truncated line of hex has a multiple of HEXCHARS_MULTIPLE_FOR_HEXDATA_LINE hex characters
MAX_LINE_LENGTH = 110
HEXCHARS_MULTIPLE_FOR_HEXDATA_LINE = 32

def is_data_line(line):
    return "=" in line and line[0] != "#"

def compute_data_label_len(line):
    return line.index("=")-1

def process_kat_item(lines_to_process, max_label_len):
    # we want hex data to be split at a multiple of HEXCHARS_MULTIPLE_FOR_HEXDATA_LINE
    # characters so we round down to nearest multiple which fits
    hexdata_len = MAX_LINE_LENGTH - max_label_len - len(" = \\")
    hexdata_len -= hexdata_len % HEXCHARS_MULTIPLE_FOR_HEXDATA_LINE

    modified_lines = []
    for line in lines_to_process:
        if not is_data_line(line):
            modified_lines.append(line + "\n")
            continue

        label_len = compute_data_label_len(line)
        line_prefix = line[:label_len] + (" "*(max_label_len - label_len)) + " = "
        data = line[label_len + len(" = "):]

        # Do not split hex data which does not overflow a line
        # Do not split string data
        # For both cases, only update indentation
        if (len(line_prefix) + len(data) <= MAX_LINE_LENGTH) or (data[0] == "\""):
            modified_lines.append(line_prefix + data + "\n")
            continue

        # Split hex data which is too long to fit in a single line
        new_lines = []
        while len(data) > 0:
            new_lines.append( line_prefix + data[:hexdata_len] + "\\\n" )
            data = data[hexdata_len:]
            line_prefix = " "*len(line_prefix)

        # Remove trailing \ from last line of multi-line hex data
        new_lines[-1] = new_lines[-1][:-2] + "\n"
        modified_lines.extend(new_lines)
    return modified_lines

def main():
    if len(sys.argv) != 2:
        print("Usage: format_kat.py <kat_file>")
        sys.exit(1)

    f = open(sys.argv[1], "r+")
    lines = f.readlines()

    # First pass through file
    # Reverse any previous multi-line KAT formatting and remove trailing linebreaks
    modified_lines = []
    multiline = "" # concatenate multi-line data into this
    for line in lines + ["\n"]:
        # Remove any trailing line break
        if line[-1] == "\n":
            line = line[:-1]

        # Remove any leading whitespace
        line = re.sub( r"^\s*", "", line )

        # Sanitize spacing around =
        if is_data_line(line):
            line = re.sub(r"\s*=\s+", " = ", line)

        # If part of multi-line data, concatenate
        if line and line[-1] == "\\":
            multiline += line[:-1]
            continue
        
        if multiline:
            line = multiline + line
            multiline = ""

        modified_lines.append( line )
    lines = modified_lines + [""]

    # Now, for each KAT item (set of lines delimited by an empty line)
    # find the maximum length of a data label (string before "=")
    # and use this to indent every data line in the KAT item
    max_label_len = 0
    lines_in_kat_item = []
    modified_lines = []
    for line in lines:
        lines_in_kat_item.append(line)
        if line == "":
            # end of kat item - flush lines_in_kat_item
            if len(lines_in_kat_item) > 1:
                modified_lines += process_kat_item(lines_in_kat_item, max_label_len)
            max_label_len = 0
            lines_in_kat_item = []
        elif is_data_line(line):
            max_label_len = max(compute_data_label_len(line), max_label_len)
    
    # for line in modified_lines:
    #     print(line, end="")
    
    # print("") # Extra newline

    f.truncate(0)
    f.seek(0)
    f.writelines(modified_lines[:-1])
    f.close()

if __name__ == "__main__":
    main()

