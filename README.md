This project was developed by my fellow colleagues and me for the Advanced Topics on Communication Netowrks of ETH Zurich, year 2021/2022. It was a fun project, where we got to implement and optimize many netowrk engineering techniques for efficient routing, load balancing, QoS management, failure detection and fast convergence. The topology is based on the Claranet network.
We have also won the course 1st prize for the most performant implementation (the goal was meeting a set of SLAs).
Have a look at the code and poster for more info! 

## Context
The project was developed targeting the [BMv2 Simple Switch Target](https://github.com/nsg-ethz/p4-learning/wiki/BMv2-Simple-Switch). The data plane is coded using [P4_16] (https://p4.org/p4-spec/docs/PSA.html).
The control plane is coded in Python using [Switch_Thrift_Api](https://nsg-ethz.github.io/p4-utils/p4utils.utils.sswitch_thrift_API.html#p4utils.utils.sswitch_thrift_API.SimpleSwitchThriftAPI).
The network was created using [mininet](http://mininet.org/)


## Group info

| Group name | 13_REXFORD |  |  |
| --- | --- | --- | --- |
| Member 1 | Francesco Intoci  | fintoci | fintoci@ethz.ch |
| Member 2 | Westermann Floris | wfloris | wfloris@ethz.ch |
| Member 3 | Bungeroth Matthias | mbungeroth | mbungeroth@ethz.ch |

## Overview

We implement dynamic failure aware routing and support routing table
calculations using either delay or number of hops as a weight metric.
To avoid congestion switches we use local load-balancing by means of flowlets
and Equal Cost Multi-Path (ECMP).
We also implemented Similar Cost Paths (SCMP) to distribute the load even
further over the network.

To handle congestion in the network, the switches will use Random Early
Detection to drop packets and avoid TCP synchronisation.
This is based on a queue length estimator using meters and counters that
approximates the queue length of each link behind the switch.
We also implement additional
[Global synchronization protection](https://www.researchgate.net/publication/301857331_Global_Synchronization_Protection_for_Bandwidth_Sharing_TCP_Flows_in_High-Speed_Links).


Since the network is small, we can precompute all possible failures and
according routing tables ahead of time.
However, computing all possible failures requires a lot of storage (>1GB).
We thus only precompute common failure scenarios and compute the others at
runtime if necessary.

Failure detections work by sending (lazy) heartbeats on all individual links.
We allow normal packets to also function as heartbeats (we call this lazy
heartbeats).We thus only send heartbeats when there is no other traffic on a
link.

Whenever a failure is detected, the switch will temporarily re-route the packets
over a Loop Free Alternative switch (LFA).
If this is not possible, it will use a remote LFA.
The controller, in the meantime, fetches the precomputed or computes the new
routing table and updates the switch.


## Individual Contributions

In this section, note down 1 or 2 sentences *per team member* outlining everyone's contribution to the project. We want to see that everybody contributed, but you don't need to get into fine details. For example, write who contributed to which feature of your solution, but do *not* write who implemented a particular function. 

### Francesco Intoci
- Routing table computation with ECMP paths.
- Implementation of per-destination LFAs.
- Implementation of PQ algorithm for RLFAs.
- Failure detection and recovery through (lazy) heartbeats.

### Westermann Floris
- Precomputation of Failure Configurations.
- Initial naive congestion detection using Meters.
- Similar Cost Multi-Path routing.
- Experimental Parameter Tuning for SCMP (Conclusion: Fewest Hop routing reigns supreme).

### Bungeroth Matthias

- Parsing/ Deparsing of headers to internal headers without ethernet (at entry/ exit ports).
- Waypointing for UDP waypointed traffic.
- First version ECMP-flowlet routing.
- TCP Global Synchronization Protection based on this [paper](https://www.researchgate.net/publication/301857331_Global_Synchronization_Protection_for_Bandwidth_Sharing_TCP_Flows_in_High-Speed_Links).
- Meter and Counter based queue length estimators.
- QOS with Random Early Detection based on estimated queue length.

