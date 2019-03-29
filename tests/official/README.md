Note on serialization hacks:

The FAR_FUTURE_SLOT (18446744073709551615) has been rewritten as a string **in the YAML file**
as it's 2^64-1 and Nim by default try to parse it into a int64 (which can represents up to 2^63-1).

The YAML file is then converted to JSON for easy input to the json serialization/deserialization
with beacon chain type support.

"18446744073709551615" is then replaced again by uint64 18446744073709551615.