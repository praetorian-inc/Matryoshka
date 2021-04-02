# Overview
Matryoshka loader is a tool that red team operators can leverage to generate shellcode for an egghunter to bypass size-limitations and performance issues commonly associated with VBA or Excel 4.0 macro payloads when creating Microsoft Office documents for targeted phishing attacks.

TODO: Need to add reference to blog post once published.

# Usage
The builder supports the following set of arguments. The user must supply an egg value along with the required architecture for the egghunter shellcode. When invoked the egghunter will search through the process memory to identify the egg, copies it to RWX memory, and then transfers control to it.

```
usage: matryoshka.py [-h] -s SHELLCODE -a ARCHITECTURE -o OUTPUT_SHELLCODE -e OUTPUT_EGG

Matryoshka Loader Shellcode Generator

optional arguments:
  -h, --help            show this help message and exit
  -s SHELLCODE, --shellcode SHELLCODE
                        Path to shellcode file
  -a ARCHITECTURE, --architecture ARCHITECTURE
                        Payload architecture to target (x86 or x86_64)
  -o OUTPUT_SHELLCODE, --output-shellcode OUTPUT_SHELLCODE
                        Path to write Matryoshka shellcode to
  -e OUTPUT_EGG, --output-egg OUTPUT_EGG
                        Path to write Egg value to
````

# Directory Structure
Matryoshka consists of two primary components. The first is the core loader written in C and the second component is the builder script written in Python. The builder is responsible for generating a preamble that handles bootstrapping tasks to launch the core loader and is responsible for passing an embedded configuration to the core loader.

- src: The src directory contains the source code for the core loader.
- builder: The builder directory contains the source code for the builder.

# References
[1] https://TODO-LINK-TO-BLOG-POST.praetorian.com/TODO
