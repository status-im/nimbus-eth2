Note:

The FAR_FUTURE_SLOT (18446744073709551615) has been rewritten as a string
as it's 2^64-1 and Nim by default try to parse it into a int64 (which can represents up to 2^63-1)