# Ecosystem-scale regexp study

Welcome to the FSE'18 artifact for the ESEC/FSE paper *"The Impact of Regular Expression Denial of Service (ReDoS) in Practice: an Empirical Study at the Ecosystem Scale"*, by J.C. Davis, C.A Coghlan, F. Servant, and D. Lee, all of Virginia Tech.

This paper describes a study in which we:
- extracted regular expressions (regexes, regexps) from npm and pypi modules
- analyzed the regexes along several dimensions

Our artifact consists of:
- code to extract regexes from npm and pypi modules
- code to analyze these regexes for super-linear performance (Table 1), degree of vulnerability (Table 2), semantic meaning (Table 3), and use of anti-patterns (Table 4)
- unique regexes collected from npm and pypi modules, without indicating the source module(s) due to security concerns

## Installation

### By hand

To install, execute the script `./configure` on an Ubuntu 16.04 machine with root privileges.
This will obtain and install the various dependencies (OS packages, REDOS detectors, npm modules, and pypi modules).
It will also initialize submodules.

The final line of this script is `echo "Configuration complete. I hope everything works!"`.
If you see this printed to the console, great!
Otherwise...alas.

### Container

To facilitate replication, we have published a containerized version of this project on hub.docker.com: XXX.
The container is based on an Ubuntu 16.04 image.
Everything works fine in this container.

## Use

Export the environment variable `ECOSYSTEM_REGEXP_PROJECT_ROOT` to ensure the scripts know how to find each other.

TODO XXX

## Directory structure

| File or Directory/    | Description | Relevance to paper |
| ---------------------:|:-------------------------------------------------------------------------------------------------:|
| .                     | introductory content | - |
| README.md             | you're in it | - |
| LICENSE               | terms of software release | - |
| INSTALL               | "install instructions" | - |
| STATUS                | claims of artifact quality | - |
| data/                 | all unique regexes we extracted from npm and pypi modules | Used to answer RQs 1-4 |
| vuln-regex-detector/  | is this regex vulnerable? (submodule) | answers RQ1 |
| degree-of-vuln/       | what is the degree of vulnerability of this regex? | answers RQ2 |
| semantic-meaning/     | what meaning does this regex appear to capture? | answers RQ3 |
| anti-patterns/        | check whether a regex contains an anti-pattern | answers RQ4 |
| visualization/        | used to produce visualizations. Mostly for posterity. | - |
| bin/                  | use with vuln-regex-detector/ | helps with RQ1 |

Each directory contains its own README for additional details.

## Style and file formats

### Style

Most of the scripts in this repository are written in Perl.
They tend to write status updates to STDERR and to emit useful output to STDOUT, though the more complex ones use a resultFile instead.

If you have dependencies on other scripts in the repo, require the invoker to define `ECOSYSTEM_REGEXP_PROJECT_ROOT`.
This environment variable should name the location of your clone of this repository.

### File formats

This project uses JSON to describe research data.
Files named `*.json` are generally JavaScript files that contain one JSON object per line.
This makes it easy to do a line-by-line analysis on the objects in the file, even if the file is large.
