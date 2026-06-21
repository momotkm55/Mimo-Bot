use std::time::Instant;

#[derive(Debug)]
pub struct Frame {
    pub _reliability: u8,
    pub order_index: Option<u32>,
    pub order_channel: u8,
    pub payload: Vec<u8>,
    pub split: Option<SplitMeta>,
}

#[derive(Debug, Clone, Copy)]
pub struct SplitMeta {
    pub count: u32,
    pub id: u16,
    pub index: u32,
}

#[derive(Debug)]
pub struct SplitBuffer {
    pub parts: Vec<Option<Vec<u8>>>,
}

#[derive(Debug, Clone)]
pub struct PendingDatagram {
    pub frame_bytes: Vec<u8>,
    pub last_sent: Instant,
    pub sends: u8,
}

pub fn parse_frames(mut data: &[u8]) -> Vec<Frame> {
    let mut frames = Vec::new();
    while data.len() >= 3 {
        let flags = data[0];
        let reliability = flags >> 5;
        let bits = u16::from_be_bytes([data[1], data[2]]) as usize;
        let len = (bits + 7) / 8;
        let mut offset = 3;
        let mut split = None;
        let mut order_index = None;
        let mut order_channel = 0u8;

        if reliability == 2 || reliability == 3 || reliability == 4 {
            if data.len() < offset + 3 {
                break;
            }
            offset += 3;
        }
        if reliability == 1 || reliability == 3 || reliability == 4 {
            if data.len() < offset + 4 {
                break;
            }
            order_index = read_triad_le(data, offset);
            order_channel = data[offset + 3];
            offset += 4;
        }
        if flags & 0x10 != 0 {
            if data.len() < offset + 10 {
                break;
            }
            let count = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let id = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            let index = u32::from_be_bytes([
                data[offset + 6],
                data[offset + 7],
                data[offset + 8],
                data[offset + 9],
            ]);
            split = Some(SplitMeta { count, id, index });
            offset += 10;
        }
        if data.len() < offset + len {
            break;
        }
        frames.push(Frame {
            _reliability: reliability,
            order_index,
            order_channel,
            payload: data[offset..offset + len].to_vec(),
            split,
        });
        data = &data[offset + len..];
    }
    frames
}

pub fn parse_ack_records(data: &[u8]) -> Vec<u32> {
    if data.len() < 3 {
        return Vec::new();
    }
    let count = u16::from_be_bytes([data[1], data[2]]) as usize;
    let mut offset = 3;
    let mut seqs = Vec::new();
    for _ in 0..count {
        let Some(record_type) = data.get(offset).copied() else {
            break;
        };
        offset += 1;
        if record_type == 0 {
            let Some(start) = read_triad_le(data, offset) else {
                break;
            };
            offset += 3;
            let Some(end) = read_triad_le(data, offset) else {
                break;
            };
            offset += 3;
            for seq in start..=end.min(start.saturating_add(512)) {
                seqs.push(seq);
            }
        } else {
            let Some(seq) = read_triad_le(data, offset) else {
                break;
            };
            offset += 3;
            seqs.push(seq);
        }
    }
    seqs
}

pub fn frame_header_len(reliability: u8, split: bool) -> usize {
    let mut len = 3;
    if reliability == 2 || reliability == 3 || reliability == 4 {
        len += 3;
    }
    if reliability == 1 || reliability == 3 || reliability == 4 {
        len += 4;
    }
    if split {
        len += 10;
    }
    len
}

fn read_triad_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(
        *data.get(offset)? as u32
            | ((*data.get(offset + 1)? as u32) << 8)
            | ((*data.get(offset + 2)? as u32) << 16),
    )
}