#![allow(dead_code)]

use bytes::Bytes;

use crate::varint::VarInt;

pub(crate) const TAG_PULL: u64 = 0x00;
pub(crate) const TAG_PUSH: u64 = 0x01;
pub(crate) const TAG_FLUSH: u64 = 0x02;
pub(crate) const TAG_FLUSH_ACK: u64 = 0x03;
pub(crate) const TAG_EOS: u64 = 0x04;
pub(crate) const TAG_EOS_ACK: u64 = 0x05;
pub(crate) const TAG_STOP: u64 = 0x06;
pub(crate) const TAG_STOP_ACK: u64 = 0x07;
pub(crate) const TAG_RESET: u64 = 0x08;
pub(crate) const TAG_RESET_ACK: u64 = 0x09;
pub(crate) const TAG_ERR_RESET: u64 = 0x0a;
pub(crate) const TAG_ERR_CONN: u64 = 0x0b;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadCommand {
    Pull,
    Stop { code: VarInt },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadEvent {
    Push { data: Bytes },
    Eos,
    StopAck { code: VarInt },
    ErrReset { code: VarInt },
    ErrConn,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteCommand {
    Push { data: Bytes },
    Flush,
    Eos,
    Reset { code: VarInt },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteEvent {
    Pull,
    FlushAck,
    EosAck,
    ResetAck { code: VarInt },
    ErrReset { code: VarInt },
    ErrConn,
}

pub(crate) type WorkerReadOut = ReadCommand;
pub(crate) type WorkerReadIn = ReadEvent;
pub(crate) type WorkerWriteOut = WriteCommand;
pub(crate) type WorkerWriteIn = WriteEvent;
pub(crate) type HyperReadIn = ReadCommand;
pub(crate) type HyperReadOut = ReadEvent;
pub(crate) type HyperWriteIn = WriteCommand;
pub(crate) type HyperWriteOut = WriteEvent;

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::varint::VarInt;

    #[test]
    fn read_eos_and_write_eos_are_distinct_typed_variants() {
        let read_eos = ReadEvent::Eos;
        let write_eos = WriteCommand::Eos;

        assert_eq!(read_eos, ReadEvent::Eos);
        assert_eq!(write_eos, WriteCommand::Eos);
    }

    #[test]
    fn tags_match_shared_wire_vocabulary() {
        assert_eq!(
            [
                TAG_PULL,
                TAG_PUSH,
                TAG_FLUSH,
                TAG_FLUSH_ACK,
                TAG_EOS,
                TAG_EOS_ACK,
                TAG_STOP,
                TAG_STOP_ACK,
                TAG_RESET,
                TAG_RESET_ACK,
                TAG_ERR_RESET,
                TAG_ERR_CONN,
            ],
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
            ]
        );
    }

    #[test]
    fn direction_aliases_preserve_semantic_frame_types() {
        let stop_code = VarInt::from_u32(51);
        let reset_code = VarInt::from_u32(52);
        let data = Bytes::from_static(b"alias payload");

        let worker_read_out: WorkerReadOut = ReadCommand::Stop { code: stop_code };
        let worker_read_in: WorkerReadIn = ReadEvent::ErrReset { code: reset_code };
        let worker_write_out: WorkerWriteOut = WriteCommand::Reset { code: reset_code };
        let worker_write_in: WorkerWriteIn = WriteEvent::ErrConn;
        let hyper_read_in: HyperReadIn = ReadCommand::Pull;
        let hyper_read_out: HyperReadOut = ReadEvent::ErrConn;
        let hyper_write_in: HyperWriteIn = WriteCommand::Flush;
        let hyper_write_out: HyperWriteOut = WriteEvent::Pull;

        assert_eq!(worker_read_out, ReadCommand::Stop { code: stop_code });
        assert_eq!(worker_read_in, ReadEvent::ErrReset { code: reset_code });
        assert_eq!(worker_write_out, WriteCommand::Reset { code: reset_code });
        assert_eq!(worker_write_in, WriteEvent::ErrConn);
        assert_eq!(hyper_read_in, ReadCommand::Pull);
        assert_eq!(hyper_read_out, ReadEvent::ErrConn);
        assert_eq!(hyper_write_in, WriteCommand::Flush);
        assert_eq!(hyper_write_out, WriteEvent::Pull);
        assert_eq!(
            WriteCommand::Push { data: data.clone() },
            WriteCommand::Push { data }
        );
        assert_eq!(WriteEvent::FlushAck, WriteEvent::FlushAck);
        assert_eq!(WriteEvent::EosAck, WriteEvent::EosAck);
    }

    #[test]
    fn stop_ack_and_reset_ack_carry_codes() {
        let stop_code = VarInt::from_u32(41);
        let reset_code = VarInt::from_u32(42);

        assert_eq!(
            ReadEvent::StopAck { code: stop_code },
            ReadEvent::StopAck { code: stop_code }
        );
        assert_eq!(
            WriteEvent::ResetAck { code: reset_code },
            WriteEvent::ResetAck { code: reset_code }
        );
    }

    #[test]
    fn push_payloads_remain_bytes() {
        let data = Bytes::from_static(b"frame payload");

        assert_eq!(
            ReadEvent::Push { data: data.clone() },
            ReadEvent::Push { data: data.clone() }
        );
        assert_eq!(
            WriteCommand::Push { data: data.clone() },
            WriteCommand::Push { data }
        );
    }
}
