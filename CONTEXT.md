# HTTP/3 connection and compression

Vocabulary for directional compression, request admission, and graceful connection shutdown.

## Language

**Request stream**:
A bidirectional stream carrying one request and its response. In h3x's symmetric-request extension, either endpoint may initiate a request stream.

**Local settings**:
The capabilities and receive limits advertised by this endpoint, including the limits of its QPACK decoder.

**Peer settings**:
The capabilities and receive limits advertised by the remote endpoint, including the limits that constrain the local QPACK encoder.

**QPACK encoder**:
The endpoint component that compresses outgoing field sections and tracks the remote decoder's knowledge of its dynamic table.

**QPACK decoder**:
The endpoint component that decompresses incoming field sections using table updates from the remote encoder.

**Encoder stream**:
A unidirectional stream carrying table instructions from an encoder to the remote decoder.
_Avoid_: Header stream; HEADERS carries the encoded field section on its request stream.

**Decoder stream**:
A unidirectional stream carrying field-section acknowledgments, stream cancellations, and insertion progress from a decoder to the remote encoder.

**Section acknowledgment**:
Confirmation that a field section with a nonzero Required Insert Count has been decoded, releasing its outstanding dynamic references at the encoder.
_Avoid_: Table-update acknowledgment.

**Insert count increment**:
Feedback reporting additional dynamic-table insertions processed by the decoder that have not already been covered by its other feedback.

**Draining**:
The HTTP/3 phase in which this endpoint accepts no new request streams while previously admitted streams can still finish. Control and QPACK streams remain available during this phase.
_Avoid_: Sent, queued as names for this lifecycle phase.

**GOAWAY boundary**:
The first request-stream ID or push ID that the sender of GOAWAY will not accept. In h3x's symmetric-request extension, both endpoints use the peer-initiated request-stream ID space; previously admitted work below that boundary may still complete.

**GOAWAY exchange**:
The h3x extension in which each endpoint explicitly initiates one local GOAWAY and receives a peer GOAWAY. Receiving a peer GOAWAY alone does not initiate local shutdown.

**Graceful termination**:
Explicitly requested termination that completes the GOAWAY exchange and finishes admitted requests before closing the transport. Control and QPACK traffic remain available during request draining.

**Closed**:
A connection whose transport has terminated and can no longer carry request, control, or QPACK traffic.
