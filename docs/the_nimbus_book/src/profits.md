# Maximise profits

> profitability depends heavily on the network and peer quality

> in terms of profitability, getting credit for slashing >>> block proposal >>> attesting

> nimbus listens to other slashers running on the network and uses that information to slash misbehaving validators - that said, we'll be adding a slasher down the line, well ahead of when it becomes more profitable to do so, when whistleblower rewards are introduced

> We should have a section on --subscribe-all-subnets - it will increase bandwidth and cpu usage, but helps the network and makes the block production algorithm perform slightly better - if we don't have such a page, it's time to start working on it
>
>when running just a few validators, we listen to a subset of the attestation traffic - in particular, we don't listen to all unaggregated traffic but instead rely on other peers to aggregate attestations for us. 
>
>that option enables listening on all unaggregated channels and when producing the block, we "top up" the aggregates that others have made with the unaggregated attestations which leads to better packing in some cases
>it costs cpu and bandwidth to process all unaggregated attestations because there's a lot of them
> if you run more than 64 validators, you'll also be listening to all traffic - the subset thing is a way to reduce operating costs for "small-time" validators


> Attestation effectiveness is a metric that directly affects your validator rewards. In simple terms, an attestation is more valuable the sooner it is put into a block and included in the chain. This interval is called the "inclusion distance" of an attestation. The smaller it is, the more profitable your validator will be. We highly recommend reading Attestant's awesome blog post on the matter here.
>
> Some stakers might notice their effectiveness is perfect, while others might see lower values such as 80%. Improving attestation effectiveness depends on a variety of factors, such as attestation network propagation, your network connectivity, the peers you are connected to. However, your network connectivity is one of the most important factors you can control to improve this metric. We have some tips to improve your connectivity here.

https://bisontrails.co/eth2-insights-validator-effectiveness/

https://www.attestant.io/posts/defining-attestation-effectiveness/
