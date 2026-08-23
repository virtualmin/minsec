# Filter corpus

One file per filter: `<name>.txt`. Each non-blank, non-`#` line is a test case:

    + <ip>  <log line>     must match and extract <ip>
    - <log line>           must not match

The core crate's `corpus` test runs every file against the built-in filter of
the same name. Add real-world lines here (with addresses rewritten to
documentation ranges) whenever a filter is changed.
