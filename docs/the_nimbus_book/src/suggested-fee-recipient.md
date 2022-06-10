# Suggested Fee Recipient

A suggested fee recipient offers an execution client, in a merged Ethereum network, a coinbase it might use. The execution client might not use this offered coinbase, unless one ensures that by running, controlling, and similarly configuring this execution client oneself.

Nimbus offers two ways to a suggested fee recipient, the `--suggested-fee-recipient` option and a per-validator recipient set using the keymanager API. Any validator without a per-validator recipient set will fall back to a `--suggested-fee-recipient` if configured.

For example, `nimbus_beacon_node --suggested-fee-recipient=0x79b53bc7a89347d3ab90789e99a0a9c58f2fea57` suggests to the execution client that `0x79b53bc7a89347d3ab90789e99a0a9c58f2fea57` might be the coinbase. If this Nimbus node has two validators, one of which has its own suggested fee recipient via the keymanager API and the other does not, the former would use its own per-validator suggested fee cipient while the latter would fall back to `0x79b53bc7a89347d3ab90789e99a0a9c58f2fea57`.
