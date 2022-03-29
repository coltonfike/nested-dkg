use std::collections::{BTreeMap, BTreeSet};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        watch::{channel, Receiver, Sender},
    },
};
use types::Id;

use tokio_stream::{wrappers::UnboundedReceiverStream, StreamMap};

pub struct Node {
    writers: BTreeMap<Id, OwnedWriteHalf>,
    stop: Sender<String>,
    pub recv: StreamMap<Id, UnboundedReceiverStream<Vec<u8>>>,
}

impl Node {
    pub async fn new(addresses: BTreeMap<Id, String>, my_id: Id) -> Node {
        let mut connect_to = BTreeMap::new();
        let mut to_connect = BTreeSet::new();
        let addr = addresses.get(&my_id).unwrap().clone();
        let mut my_addr = "0.0.0.0:".to_string();
        my_addr.push_str(addr.split(":").collect::<Vec<_>>()[1]);

        for (id, addr) in addresses {
            if my_id < id {
                connect_to.insert(id, addr);
            } else if my_id > id {
                to_connect.insert(id);
            }
        }

        let incoming_streams = tokio::spawn(listen(my_addr, to_connect));

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let outgoing_streams = connect(my_id, connect_to).await;
        let incoming_streams = incoming_streams.await.expect("failed to finish listening");

        let mut recv = StreamMap::new();
        let mut writers = BTreeMap::new();
        let (stop, rx) = channel("go".to_owned());
        for (id, stream) in outgoing_streams {
            let (reader, writer) = stream.into_split();
            let (sender, receiver) = unbounded_channel();
            tokio::spawn(read_from_sock(reader, sender, rx.clone()));
            recv.insert(id, UnboundedReceiverStream::new(receiver));
            writers.insert(id, writer);
        }
        for (id, stream) in incoming_streams {
            let (reader, writer) = stream.into_split();
            let (sender, receiver) = unbounded_channel();
            tokio::spawn(read_from_sock(reader, sender, rx.clone()));
            recv.insert(id, UnboundedReceiverStream::new(receiver));
            writers.insert(id, writer);
        }

        Self {
            writers,
            stop,
            recv,
        }
    }

    pub async fn broadcast(&mut self, msg: &[u8], to: Vec<Id>) {
        let mut to_send = msg.len().to_be_bytes().to_vec();
        to_send.append(&mut msg.to_vec());
        for id in to {
            self.writers
                .get_mut(&id)
                .unwrap()
                .write_all(&to_send)
                .await
                .expect("failed to write message");
        }
    }

    pub fn shutdown(&self) {
        self.stop
            .send("stop".to_owned())
            .expect("failed to shutdown network");
    }
}

async fn read_from_sock(
    mut reader: OwnedReadHalf,
    sender: UnboundedSender<Vec<u8>>,
    mut stop: Receiver<String>,
) {
    let mut buf = [0; 8];
    loop {
        tokio::select! {
            _ = stop.changed() => {
                let s = stop.borrow_and_update();
                if *s == "stop" {
                    break;
                }
            }
            Ok(_) = reader.read_exact(&mut buf) => {
                let msg_size: usize = usize::from_be_bytes(buf);
                let mut read = vec![0; msg_size];
                reader.read_exact(&mut read).await.unwrap();
                sender.send(read.to_vec()).unwrap();
            },
        }
    }
}

async fn listen(my_addr: String, to_connect: BTreeSet<Id>) -> BTreeMap<Id, TcpStream> {
    let listener = TcpListener::bind(my_addr.clone())
        .await
        .expect("failed to bind to address");
    let mut streams = BTreeMap::new();

    for _ in 0..to_connect.len() {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("failed to accept incoming connection");

        let mut buf = [0; 8];

        stream
            .read_exact(&mut buf)
            .await
            .expect("failed to read id");

        let msg_size: usize = usize::from_be_bytes(buf);
        let mut read = vec![0; msg_size];
        stream.read_exact(&mut read).await.unwrap();

        let id: Id = bincode::deserialize(&read).expect("failed to deserialize id");
        streams.insert(id, stream);
    }
    streams
}

async fn connect(my_id: Id, connect_to: BTreeMap<Id, String>) -> BTreeMap<Id, TcpStream> {
    let mut id_buf = bincode::serialize(&my_id).expect("failed to serialize id");
    let mut to_send = id_buf.len().to_be_bytes().to_vec();
    to_send.append(&mut id_buf);

    let mut streams = BTreeMap::new();
    for (id, addr) in connect_to {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("failed to connect to node");
        stream.write_all(&to_send).await.expect("failed to send id");
        streams.insert(id, stream);
    }

    streams
}
