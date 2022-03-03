use std::collections::BTreeMap;

use crate::dkg::{combine_dealings, generate_shares};

use networking::Node;
use tokio_stream::StreamExt;
use types::{
    bivariate::{Dealing, Message},
    Id,
};

pub async fn run_local_dkg(my_id: (usize, usize), nodes: (u32, u32), threshold: (usize, usize)) {
    let mut addresses = BTreeMap::new();
    let mut port = 30000;

    for i in 0..nodes.0 {
        for j in 0..nodes.1 {
            addresses.insert(
                Id::Bivariate(i as usize, j as usize),
                format!("127.0.0.1:{}", port),
            );
            port += 1;
        }
    }

    run_single_node(my_id, nodes, threshold, addresses).await;
}

async fn run_single_node(
    my_id: (usize, usize),
    nodes: (u32, u32),
    threshold: (usize, usize),
    addresses: BTreeMap<Id, String>,
) {
    let ids = addresses
        .iter()
        .filter_map(|(id, _)| {
            if Id::Bivariate(my_id.0, my_id.1) == *id {
                None
            } else {
                Some(*id)
            }
        })
        .collect::<Vec<Id>>();

    let group_ids = addresses
        .iter()
        .filter_map(|(id, _)| match id {
            Id::Bivariate(i, j) => {
                if *i == my_id.0 && *j != my_id.1 {
                    Some(*id)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect::<Vec<Id>>();

    let mut node = Node::new(addresses, Id::Bivariate(my_id.0, my_id.1)).await;

    let dealing = generate_shares(nodes, threshold);
    let (serialized_coefficients, serialized_shares) = dealing.serialize();
    let msg = Message::Shares(serialized_coefficients, serialized_shares);

    let mut dealings = vec![dealing];

    node.broadcast(&bincode::serialize(&msg).unwrap(), ids)
        .await;

    // n - 1 since we already know our shares
    for _ in 0..(nodes.0 * nodes.1) - 1 {
        let t = std::time::Instant::now();
        let (_, msg) = node.recv.next().await.expect("failed to read message");

        let t = std::time::Instant::now();
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
    let pk = coefficients.individual_public_key((my_id.0 as u32, my_id.1 as u32));

    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
}
