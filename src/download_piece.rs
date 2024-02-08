
#[path = "./utils.rs"]
mod utils;

#[path = "./peers.rs"]
mod peers;

use crate::models::Torrent;

use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;

#[derive(Debug)]
enum DownloadPieceState {
    Handshake,
    Bitfield,
    Interested,
    Unchoke,
    Request,
}

const BLOCK_SIZE: usize = 16*1024;

pub async fn download_piece(torrent: &Torrent, piece_index: u32) -> Vec<u8> {
    dbg!(torrent);
    let mut state = DownloadPieceState::Handshake;
    let peer = utils::get_tracker(torrent).await.unwrap()[0];

    dbg!(&peer);
    let mut stream = TcpStream::connect(&peer).await.unwrap();

    let lenght = torrent.info.extract_length().unwrap() as u32;
    let piec_lenght = torrent.info.plength as u32;

    let total_number_of_pieces: u32 = (lenght + piec_lenght - 1) / piec_lenght ;
    let this_pieces_size = if piece_index == total_number_of_pieces - 1 {
        lenght % piec_lenght
    } else {
        piec_lenght
    };
    let block_size: u32 = BLOCK_SIZE.try_into().unwrap();

    let number_of_blocks: u32 = (this_pieces_size + block_size - 1) / block_size;

    //dbg!(this_pieces_size);
    //dbg!(number_of_blocks);
    loop {
        //dbg!(&state);
        match state {
            DownloadPieceState::Handshake => {
                let peer_id_hash = perform_peer_handshake(torrent, &mut stream).await.unwrap();
                dbg!(hex::encode(peer_id_hash));
                println!("Handshake");
                // TODO: validate peer id: [u8; 20]
                state = DownloadPieceState::Bitfield;
            },
            DownloadPieceState::Bitfield => {
                let msg = PeerMessage::read_from_tcp_stream(&mut stream).await.unwrap();
                dbg!(&msg);
                match msg {
                    PeerMessage::Bitfield(_payload) => {
                        state = DownloadPieceState::Interested;
                    },
                    _ => { panic!("Expected Bitfield"); },
                };
            },
            DownloadPieceState::Interested => {
                let raw_msg = PeerMessage::to_bytes(&PeerMessage::Interested).unwrap();
                dbg!(&raw_msg);
                stream.write(&raw_msg).await.unwrap();
                state = DownloadPieceState::Unchoke;
            },
            DownloadPieceState::Unchoke => {
                let msg = PeerMessage::read_from_tcp_stream(&mut stream).await.unwrap();
                dbg!(&msg);
                match msg {
                    PeerMessage::Unchoke => {
                        state = DownloadPieceState::Request;
                    },
                    _ => {
                        panic!("Expected Bitfield");
                    },
                };
                // TODO: validate pieces based in sha1 hash of torrent.info.pieces
            },
            DownloadPieceState::Request => {
                dbg!(block_size);
                let mut piece: Vec<u8> = Vec::with_capacity(torrent.info.extract_length().unwrap());
                for i in 0..number_of_blocks {
                    //dbg!(i);
                    let this_blocks_size: u32 = if i == number_of_blocks - 1 && this_pieces_size % block_size != 0 {
                        (this_pieces_size % block_size).try_into().unwrap()
                    } else {
                        u32::try_from(block_size).unwrap()
                    };
                    //dbg!(this_blocks_size);
                    let request_payload = RequestPayload {
                        index: piece_index,
                        begin: i*block_size,
                        length: this_blocks_size,
                    };
                    //dbg!(&request_payload);
                    let raw_request_msg = PeerMessage::to_bytes(&PeerMessage::Request(request_payload)).unwrap();
                    //dbg!(&raw_request_msg);
                    stream.write(&raw_request_msg).await.unwrap();
                    let response_msg = PeerMessage::read_from_tcp_stream(&mut stream).await.unwrap();
                    //let mut dbg_buf = vec![0; 1];
                    //stream.read_exact(&mut dbg_buf).unwrap();
                    //dbg!(&response_msg);
                    match response_msg {
                        PeerMessage::Piece(PiecePayload {
                            index: _,
                            begin: _,
                            block,
                        }) => {
                            // TODO: verify index, begin
                            piece.extend_from_slice(&block);
                        },
                        _ => {
                            panic!("Expected PeerMessage::Piece, got: {:?}", response_msg);
                        },
                    };
                };
                return piece;
            },
        }
    }
}



async fn perform_peer_handshake(t: &Torrent,  stream: &mut TcpStream) -> anyhow::Result<[u8; 20]> {
    // let mut stream = TcpStream::connect(peer).unwrap();
    let hs = peers::Handshake::new(t.info.hash()?, b"00112233445566778899".to_owned());
    stream.write_all(&hs.to_bytes()).await?;
    let mut buf = [0; peers::HANDSHAKE_LEN];
    stream.read_exact(&mut buf).await?;
    //eprintln!("{buf:?}");
    let hs_resp = peers::Handshake::from_bytes(&buf)?;
    println!("Peer ID: {}", hex::encode(hs_resp.peer_id));
    Ok(hs_resp.peer_id)
}

#[derive(Debug)]
enum PeerMessage {
    Bitfield(Vec<u8>),
    Interested,
    Unchoke,
    Request(RequestPayload),
    Piece(PiecePayload),
}

impl PeerMessage {
    const ID_BITFIELD: u8 = 5;
    const ID_INTERESTED: u8 = 2;
    const ID_UNCHOKE: u8 = 1;
    const ID_REQUEST: u8 = 6;
    const ID_PIECE: u8 = 7;

    async fn read_from_tcp_stream(stream: &mut TcpStream) -> anyhow::Result<PeerMessage> {
        // let mut stream = TcpStream::connect(peer)?;
        // read length prefix (4 bytes)
        let mut length_buf = [0u8; 4];
        stream.read_exact(&mut length_buf).await.unwrap();
        let length = u32::from_be_bytes(length_buf);
        // read message id (1 byte)
        let mut id_buf = [0u8; 1];
        stream.read_exact(&mut id_buf).await.unwrap();
        let id = u8::from_be_bytes(id_buf);
        // read payload (of length as indicated in prefix bytes)
        //dbg!(length);
        //dbg!(id);
        // let payload_length: usize = length.try_into().unwrap() - 1;
        let payload_length: usize = <u32 as TryInto<usize>>::try_into(length).unwrap() - 1;
        //dbg!(payload_length);
        let mut payload_buf: Vec<u8> = vec![0; payload_length];
        stream.read_exact(&mut payload_buf).await.unwrap();
        //dbg!(&payload_buf);
        let msg = match id {
            PeerMessage::ID_BITFIELD => Ok(PeerMessage::Bitfield(payload_buf)),
            PeerMessage::ID_INTERESTED => Ok(PeerMessage::Interested),
            PeerMessage::ID_UNCHOKE => Ok(PeerMessage::Unchoke),
            PeerMessage::ID_REQUEST => Ok(PeerMessage::Request(RequestPayload::from_bytes(&payload_buf)?)),
            PeerMessage::ID_PIECE => Ok(PeerMessage::Piece(PiecePayload::from_bytes(payload_buf)?)),
            _ =>  Err(anyhow::Error::msg("Unkown")),
        };
        msg
    }
    
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        match self {
            PeerMessage::Bitfield(_payload_buf) => {
                todo!()
            },
            PeerMessage::Interested => {
                let length: u32 = 1;
                let id: u8 = PeerMessage::ID_INTERESTED;
                buffer.extend_from_slice(&length.to_be_bytes());
                buffer.push(id);
            },
            PeerMessage::Unchoke => {
                todo!()
            },
            PeerMessage::Request(request_payload) => {
                let length: u32 = 1 + 3*4;
                let id: u8 = PeerMessage::ID_REQUEST;
                buffer.extend_from_slice(&length.to_be_bytes());
                buffer.push(id);
                buffer.extend_from_slice(&request_payload.index.to_be_bytes());
                buffer.extend_from_slice(&request_payload.begin.to_be_bytes());
                buffer.extend_from_slice(&request_payload.length.to_be_bytes());
            },
            PeerMessage::Piece(_piece_payload) => {
                todo!()
            },
        }
        Ok(buffer)
    }
}

#[derive(Debug)]
struct RequestPayload {
    index: u32,
    begin: u32,
    length: u32,
}
impl RequestPayload {
    fn from_bytes(raw: &[u8]) -> anyhow::Result<RequestPayload> {
        if raw.len() != 12 {
            return Err( anyhow::Error::msg("Cannot parse payload as RequestPayload"));
        }
        let index = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        let begin = u32::from_be_bytes(raw[4..8].try_into().unwrap());
        let length = u32::from_be_bytes(raw[8..12].try_into().unwrap());
        Ok(RequestPayload {
            index,
            begin,
            length,
       })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct PiecePayload {
    index: u32,
    begin: u32,
    block: Vec<u8>,
}
impl PiecePayload {
    fn from_bytes(mut raw: Vec<u8>) -> anyhow::Result<PiecePayload> {
        if raw.len() < 8 {
            return Err(anyhow::Error::msg("Cannot parse payload as PiecePayload"));
        }
        let index = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        let begin = u32::from_be_bytes(raw[4..8].try_into().unwrap());
        let block = raw.split_off(8);
        Ok(PiecePayload {
            index,
            begin,
            block,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task;
use std::collections::VecDeque;
use futures::stream::{ FuturesUnordered, StreamExt };
use std::net::SocketAddrV4;

#[derive(Debug)]
pub enum DownloadError {
    PeerError { peer: SocketAddrV4, piece_index: u32, error: anyhow::Error },
}

use std::fmt;
impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DownloadError::PeerError { ref peer, piece_index, ref error } => {
                write!(f, "Error with peer {:?} on piece {}: {}", peer, piece_index, error)
            },
        }
    }
}

impl std::error::Error for DownloadError {}

struct DownloadSuccess {
    peer: SocketAddrV4,
    piece_index: u32,
    piece_data: Vec<u8>,
}


pub async fn download_pieces(torrent: Arc<Torrent>) -> anyhow::Result<Vec<u8>> {
    let lenght = torrent.info.extract_length().unwrap() as u32;
    let piec_lenght = torrent.info.plength as u32;

    let number_of_pieces = (lenght + piec_lenght - 1) / piec_lenght;

    let peers = utils::get_tracker(Arc::as_ref(&torrent)).await.unwrap();
    let peer_queue = Arc::new(Mutex::new(VecDeque::from(peers)));

    let mut futures = FuturesUnordered::new();

    for piece_index in 0..number_of_pieces {
        let torrent_clone = torrent.clone();
        let peer_queue_clone = peer_queue.clone();
        let future = task::spawn(try_download_piece(piece_index, torrent_clone, peer_queue_clone));
        futures.push(future);
    }
    
    let mut pieces = vec![None; number_of_pieces.try_into().unwrap()];
    while let Some(result) = futures.next().await {
        match result {
            Ok(Ok(DownloadSuccess {
                peer,
                piece_index,
                piece_data,
            })) => {
                peer_queue.lock().await.push_front(peer);
                pieces[piece_index as usize] = Some(piece_data);
            },
            Ok(Err(DownloadError::PeerError {
                peer,
                piece_index,
                error: _,
            })) => {
                let torrent_clone = torrent.clone();
                peer_queue.lock().await.push_back(peer);
                let peer_queue_clone = peer_queue.clone();
                let future = task::spawn(try_download_piece(piece_index, torrent_clone, peer_queue_clone));
                futures.push(future);
            }
            Err(e) => return Err(anyhow::Error::msg(e.to_string())), // Handle spawn errors
        }
    }
    // Assemble the downloaded pieces into the final file content
    Ok(pieces.into_iter().map(|piece| piece.unwrap()).flatten().collect())

}

async fn try_download_piece(
    piece_index: u32,
    torrent: Arc<Torrent>,
    peer_queue: Arc<Mutex<VecDeque<SocketAddrV4>>>,
) -> Result<DownloadSuccess, DownloadError> {
    loop {
        let peer_option = {
            let mut queue = peer_queue.lock().await;
            queue.pop_front()
        };

        if let Some(peer) = peer_option {
            match download_piece2(piece_index, torrent, &peer).await {
                Ok(piece_data) => return Ok(DownloadSuccess {
                    peer,
                    piece_index,
                    piece_data,
                }),
                Err(error) => return Err(DownloadError::PeerError {
                    peer,
                    piece_index,
                    error,
                }),
            }
        }

    }
}

#[path="./peer_messages_mod.rs"]
mod peer_messages_mod;
use crate::download_piece::peer_messages_mod::PeerMessage2; 
use crate::download_piece::peer_messages_mod::PiecePayload2; 
use crate::download_piece::peer_messages_mod::RequestPayload2; 

pub async fn download_piece2(piece_index: u32, torrent: Arc<Torrent>, peer: &SocketAddrV4) -> anyhow::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(peer).await?;
    perform_peer_handshake(Arc::as_ref(&torrent), &mut stream).await?;
    let msg = PeerMessage2::from_reader(&mut stream).await?;
    if !matches!(msg, PeerMessage2::Bitfield(_payload)) {
        return Err(anyhow::Error::msg("Expected Bitfield reponse"));
    }
    PeerMessage2::Interested.write_to(&mut stream).await?;
    let msg = PeerMessage2::from_reader(&mut stream).await?;
    if !matches!(msg, PeerMessage2::Unchoke) {
        return Err(anyhow::Error::msg("Expected Unchoke reponse"));
    }
    // request blocks of piece
    let number_of_blocks = torrent.number_of_blocks(piece_index);
    let mut blocks: Vec<Option<Vec<u8>>> = vec![None; number_of_blocks.try_into().unwrap()];
    
    const MAX_REQUESTS: u32 = 10;
    let max_requests = u32::min(MAX_REQUESTS, number_of_blocks);
    let mut active_requests: VecDeque<u32> = VecDeque::with_capacity(MAX_REQUESTS.try_into().unwrap());
    for block_index in 0..max_requests {
        send_request(block_index, piece_index, torrent.clone(), &mut stream, &mut active_requests).await?;
    }
    for block_index in max_requests..number_of_blocks {
        if active_requests.len() < max_requests.try_into().unwrap() {
            send_request(block_index, piece_index, torrent.clone(), &mut stream, &mut active_requests).await?;
        }
        else {
            handle_response(&mut stream, &mut active_requests, &mut blocks).await?;
            send_request(block_index, piece_index, torrent.clone(), &mut stream, &mut active_requests).await?;
        }
    }
    while !active_requests.is_empty() {
        handle_response(&mut stream, &mut active_requests, &mut blocks).await?;
    }
    let piece: Vec<u8> = blocks
        .into_iter()
        .map(|block| block.expect("All blocks must be successfully downloaded"))
        .flatten()
        .collect();
    if torrent.is_piece_hash_correct(&piece, piece_index) {
        Ok(piece)
    }
    else {
        Err(anyhow::Error::msg( "Piece hash mismatch"))
    }
}

async fn send_request(
    block_index: u32, piece_index: u32, torrent: Arc<Torrent>,
    stream: &mut TcpStream, active_requests: &mut VecDeque<u32>)
    -> anyhow::Result<()> {
    let request_payload = RequestPayload2 {
        index: piece_index,
        begin: block_index*(u32::try_from(BLOCK_SIZE).unwrap()),
        length: torrent.block_size(block_index, piece_index)
    };
    PeerMessage2::Request(request_payload).write_to(stream).await?;
    active_requests.push_back(block_index);
    Ok(())
}

async fn handle_response(stream: &mut TcpStream, active_requests: &mut VecDeque<u32>, piece: &mut Vec<Option<Vec<u8>>>) -> anyhow::Result<()> {
    let response_msg = PeerMessage2::from_reader(stream).await?;
    match response_msg {
        PeerMessage2::Piece(PiecePayload2 {
            index: _,
            begin,
            block,
        }) => {
            let block_index = begin / (u32::try_from(BLOCK_SIZE).unwrap());
            piece[usize::try_from(block_index).unwrap()] = Some(block);
            active_requests.retain(|&x| x != block_index);
            Ok(())
        },
        _ => {
            Err(anyhow::Error::msg(format!("Expected PeerMessage::Piece with payload, got {:?}", response_msg) ))
        },
    }
}

