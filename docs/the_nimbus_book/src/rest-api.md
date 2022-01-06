# REST API

Nimbus exposes a high-performance implementation of the [Beacon Node API](https://ethereum.github.io/beacon-APIs/).

The API is a `REST` interface accessed via `HTTP`. The API should not, unless protected by additional security layers, be exposed to the public Internet as the API includes multiple endpoints which could open your node to denial-of-service (DoS) attacks through endpoints triggering heavy processing.

The API can be used with any conforming consumer, including alternative validator client implementations, explorers and tooling.

## Configuration

By default, the REST interace is disabled. To enable it, use the `--rest` option when starting the beacon node, then access the API from http://localhost:5052/.

By default, only connections from the same machine are entertained. The port and listening address can be further configured through the options `--rest-port` and `--rest-address`.

## Specification

The specification is documented [here](https://ethereum.github.io/beacon-APIs/).

See the Readme [here](https://github.com/ethereum/beacon-APIs).

## Quickly test your tooling against Nimbus

 The [Nimbus REST api](https://nimbus.guide/rest-api.html) is now available from:

* http://testing.mainnet.beacon-api.nimbus.team/
* http://unstable.mainnet.beacon-api.nimbus.team/
* http://unstable.prater.beacon-api.nimbus.team/

Note that right now these are very much unstable testing instances. They may be unresponsive at times - so **please do not rely on them for validation**. We may also disable them at any time.
