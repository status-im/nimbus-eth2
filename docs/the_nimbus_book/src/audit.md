# Security Audit

## Summary

Nimbus has undergone an extensive multi-vendor ([ConsenSys Diligence](https://consensys.net/diligence/), [NCC Group](https://www.nccgroup.com/uk/), and [Trail of Bits](https://www.trailofbits.com/)) security assessment over a period of several months.
During that process, we were notified of several issues within the codebase.
These issues have been addressed, contributing significantly to the overall security of Nimbus and other applications that use its libraries.

Additionally, as a result of the work done from our security vendors, we have incoroprated many new security processes and tooling to improve our ability to find security issues in the future.

For more information on the issues and how they were addressed, the interested reader should direct themselves to the [scoped repositories](https://github.com/status-im/nimbus-eth2/labels?q=audit); all reported issues and their mitigations are open to the public.

## History

Back in May of 2020, Status and the Nimbus Team posted a [Request for Proposal document](https://our.status.im/nimbus-eth2-0-security-audit-request-for-proposal/) regarding the [security assessment](https://our.status.im/what-is-a-security-audit-when-you-should-get-one-and-how-to-prepare/) of the [nimbus-eth2](https://github.com/status-im/nimbus-eth2) repository (formerly `nim-beacon-chain`) and its software dependencies.

After thoroughly vetting and weighing the submitted proposals, three security vendors  were chosen to review the codebase for a timeline of approximately [three months](https://notes.status.im/7D73zDPyQxOUWw4ejEn6oQ?view#).

The kickoff announcement can be read [here](https://our.status.im/nimbus-beacon-chain-assessment-kickoff/).

We separated the codebase into sub-topics with various tasks.
These tasks were then broken up and assigned to the vendor(s) with the required expertise.

The desired deliverable outcome was GitHub issues in the repositories under review, which is a shift from the standard “assessment report” provided by most security assessments in the space.
You can view the issues [here](https://github.com/status-im/nimbus-eth2/labels?q=audit).

To be very clear, we did not engage in this security assessment to get a stamp of approval from the security community.
All of the effort put into creating this process and engaging the community was in the service of increasing the level of security and code quality of the Nimbus software.

