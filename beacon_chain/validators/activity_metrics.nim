import metrics
export metrics

const delayBuckets =
  [-Inf, -4.0, -2.0, -1.0, -0.5, -0.1, -0.05, 0.05, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, Inf]

# The "sent" counters capture messages that were sent via this beacon node
# regardless if they were produced internally or received via the REST API.
#
# Counters and histograms for timing-sensitive messages, only counters for
# the rest (aggregates don't affect rewards, so timing is less important)

declarePublicCounter beacon_attestations_sent, "Number of attestations sent by the node"

declarePublicCounter beacon_aggregates_sent,
  "Number of beacon chain attestations sent by the node"

declarePublicHistogram beacon_attestation_sent_delay,
  "Time(s) between expected and actual attestation send moment", buckets = delayBuckets

declarePublicCounter beacon_blocks_sent, "Number of beacon blocks sent by this node"

declarePublicHistogram beacon_blocks_sent_delay,
  "Time(s) between expected and actual block send moment", buckets = delayBuckets

declarePublicCounter beacon_sync_committee_messages_sent,
  "Number of sync committee messages sent by the node"

declarePublicHistogram beacon_sync_committee_message_sent_delay,
  "Time(s) between expected and actual sync committee message send moment",
  buckets = delayBuckets

declarePublicCounter beacon_sync_committee_contributions_sent,
  "Number of sync committee contributions sent by the node"
