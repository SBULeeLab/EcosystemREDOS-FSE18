# Summary

This directory contains files with all of the unique regexes we identified in npm and pypi modules (summarized in Table 1).

Untar the "uniquePatterns.tgz" file and you'll get one file for npm and one file for pypi.
Each file is a pseudo-JSON file, with one JSON object defined on each line.
Each such object has a single key: "pattern".
The value of this key is a unique string we found in the source of at least one module in the corresponding eceosystem.

The `anonymize.py` script is a one-off to convert internal files into these anonymized files.
