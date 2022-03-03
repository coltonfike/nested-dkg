use std::collections::BTreeMap;

use crate::dkg::{combine_dealings, generate_shares, get_public_key};

use networking::Node;
use tokio_stream::StreamExt;
use types::{
    univariate::{Dealing, Message},
    Id,
};

pub async fn run_local_dkg(my_id: usize, n: u32, t: usize) {
    let mut addresses = BTreeMap::new();
    let mut port = 30000;

    for i in 0..n {
        addresses.insert(Id::Univariate(i as usize), format!("127.0.0.1:{}", port));
        port += 1;
    }

    run_single_node(my_id, n, t, addresses).await;
}

async fn run_single_node(my_id: usize, n: u32, t: usize, addresses: BTreeMap<Id, String>) {
    let ids = addresses
        .iter()
        .filter_map(|(id, _)| {
            if Id::Univariate(my_id) == *id {
                None
            } else {
                Some(*id)
            }
        })
        .collect::<Vec<Id>>();
    let mut node = Node::new(addresses, Id::Univariate(my_id)).await;

    let dealing = generate_shares(n, t);
    let (serialized_coefficients, serialized_shares) = dealing.serialize();
    let msg = Message::Shares(serialized_coefficients, serialized_shares);

    let mut dealings = vec![dealing];

    node.broadcast(&bincode::serialize(&msg).unwrap(), ids)
        .await;

    // n - 1 since we already know our shares
    for _ in 0..n - 1 {
        let (_, msg) = node.recv.next().await.expect("failed to read message");
        let msg: Message = bincode::deserialize(&msg).unwrap();
        match msg {
            Message::Shares(serialized_coefficients, serialized_shares) => {
                dealings.push(Dealing::deserialize(
                    serialized_coefficients,
                    serialized_shares,
                ));
            }
        }
    }

    let (coefficients, sk) = combine_dealings(my_id, &dealings);
    let pk = get_public_key(my_id, &coefficients);

    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();

    println!("Node {} finished", my_id);
}
