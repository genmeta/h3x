# HTTP/3 connection lifecycle

Vocabulary for request admission and graceful connection shutdown.

## Language

**Draining**:
The HTTP/3 phase in which this endpoint accepts no new request streams while previously admitted streams can still finish. Control and QPACK streams remain available during this phase.
_Avoid_: Sent, queued as names for this lifecycle phase.

**GOAWAY boundary**:
The first request-stream ID or push ID that the sender of GOAWAY will not accept. Previously admitted work below that boundary may still complete.

**Closed**:
A connection whose transport has terminated and can no longer carry request, control, or QPACK traffic.
