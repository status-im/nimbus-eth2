## Builder Proposal Delay Tolerance

You can now configure the builder proposal delay tolerance (MEV block builder timeout) via the following flag:

```
--builder-proposal-delay-tolerance=<milliseconds>
```

- **Default value:** 1500 (milliseconds)
- **Description:** Timeout for builder proposal delay tolerance. Increasing this value may allow the builder extra time to gather more transactions or MEV value, potentially improving block value and network efficiency. Lower values may reduce block proposal latency.

**Example usage:**

```
./nimbus_beacon_node --builder-proposal-delay-tolerance=2000
```

This option is useful for node operators who wish to tune performance for different environments or experiment with MEV builder timing.
