# Logging strategy

This document describes the overall logging strategy of NBC.
This is a suggested guideline, rare events can have a higher logging level
than suggested in the guideline for example at beacon node start or stop.

The main objectives are:
- INFO log level or higher should be suitable for long-term use, i.e. running for months or weeks. Logs are the users' main interface their beacon node and validators. In particular it should not be a denial-of-service vector, either by leading to high CPU usage of the console or filling disk space at an unsustainable rate.
- INFO logs or higher should be target at users, logs only relevant to devs should be relegated to DEBUG or TRACE or commented out.
- DEBUG log level should still be readable by visual inspection during a slot time (6 seconds).

Here is the suggestion of content per log level

- Fatal: Node will crash
- Error: Bugs or critical unexpected behaviors
  - node cannot proceed with task
  - node consistency is compromised
- Warning: Errors that can be expected or handled
  - networking issue,
  - node cannot proceed with task but can recover or work in degraded mode (invalid bootstrap address, out of Infura requests)
- Notice: Important user and validator info and one-time events
  - node start/quit,
  - log about validator funds,
  - own PoS attestations,
  - own PoS blocks,
  - chain reached finality,
  - validators have been slashed (i.e. might indicate malicious activity or network/chain split)
- Info: standard user target
  - Networking or consensus information
- Debug: dev and debugging users
  - Common networking activity (new peers, kick peers, timeouts),
  - consensus/proof-of-stake various processing,
- Trace: dev only
  - Keep-alive,
  - routine tasks schedules
  - "spammy" tasks that clutter debugging (attestations received, status/control messages)

Logs done at high frequency should be summarized even at trace level to avoid drowning other subsystems.
For example they can use an uint8 counter with
```
proc myHighFreqProc() =
  var counter {.threadvar.}: uint8
  if counter == 255:
    trace "Total of 255 myHighFreqProc call"
  counter += 1
```
