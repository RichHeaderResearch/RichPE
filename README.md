# Rich Header Research

The Rich header is an undocumented header contained within PE files compiled and linked using the Microsoft toolchain. It contains information about the build environment that the PE file was created in. If you want to learn more about the Rich header, check out these excellent articles:

 * https://www.ntcore.com/files/richsign.htm
 * https://bytepointer.com/articles/the_microsoft_rich_header.htm

Prior research on the Rich header has shown that it is very useful for malware analysis:

 * https://www.sec.in.tum.de/i20/publications/finding-the-needle-a-study-of-the-pe32-rich-header-and-respective-malware-triage
 * https://securelist.com/the-devils-in-the-rich-header/84348/
 * http://ropgadget.com/posts/richheader_hunting.html

This repository contains our own research on the Rich header, which includes the RichPE metadata hash and a tool that checks whether the metadata within the Rich header is corroborated by other PE file metadata.

## RichPE:

Implementation of the RichPE metadata hash.

```
usage: python3 richpe.py [any # of file paths]

example: python3 richpe.py /path/to/file

example: python3 richpe.py /path/to/directory/*
```

## Spoof Check:

Checks that the metadata within a file's Rich header does not contradict the other metadata contained within it.

```
usage: python3 spoof_check.py [any # of file paths]

example: python3 spoof_check.py /path/to/file

example: python3 spoof_check.py /path/to/directory/*
```

## Dependencies:

Both richpe.py and spoof_check.py depend upon the pefile library.

```
pip3 install pefile
```

