use super::*;
use futures::future::try_join_all;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// Accepts every connection the sender opens (one control plus the bulk
/// stripe) and completes once any of them delivers a frame.
pub fn listener(address: SocketAddr) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&address).await.unwrap();
        let (tx_frame, mut rx_frame) = channel::<Bytes>(100);
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let tx_frame = tx_frame.clone();
                tokio::spawn(async move {
                    let mut transport = Framed::new(socket, LengthDelimitedCodec::new());
                    while let Some(Ok(frame)) = transport.next().await {
                        let _ = tx_frame.send(frame.freeze()).await;
                    }
                });
            }
        });
        assert!(rx_frame.recv().await.is_some());
    })
}

#[tokio::test]
async fn send() {
    // Make the network sender.
    let (tx, rx) = channel(1);
    let mut sender = NetSender::new(rx);
    tokio::spawn(async move {
        sender.run().await;
    });

    // Run a TCP server.
    let address = "127.0.0.1:5000".parse::<SocketAddr>().unwrap();
    let handle = listener(address);

    // Send a message.
    let message = NetMessage(Bytes::from("Ok"), vec![address], MessageClass::Control);
    let _ = tx.send(message).await;

    // Ensure the server received the message (ie. it did not panic).
    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn broadcast() {
    // Make the network sender.
    let (tx, rx) = channel(1);
    let mut sender = NetSender::new(rx);
    tokio::spawn(async move {
        sender.run().await;
    });

    // Run 3 TCP servers.
    let (handles, addresses): (Vec<_>, Vec<_>) = (0..3)
        .map(|x| {
            let address = format!("127.0.0.1:{}", 5100 + x)
                .parse::<SocketAddr>()
                .unwrap();
            (listener(address), address)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .unzip();

    // Broadcast a message.
    let message = NetMessage(Bytes::from("Ok"), addresses, MessageClass::Bulk);
    let _ = tx.send(message).await;

    // Ensure all servers received the broadcast.
    assert!(try_join_all(handles).await.is_ok());
}

#[tokio::test]
async fn receive() {
    // Make the network receiver.
    let address = "127.0.0.1:5200".parse::<SocketAddr>().unwrap();
    let (tx, mut rx): (Sender<String>, _) = channel(1);
    let receiver = NetReceiver::new(address.clone(), tx);
    tokio::spawn(async move {
        receiver.run().await;
    });
    sleep(Duration::from_millis(50)).await;

    // Send a message.
    let message = "Ok";
    let bytes = Bytes::from(bincode::serialize(message).unwrap());
    let stream = TcpStream::connect(address).await.unwrap();
    let mut transport = Framed::new(stream, LengthDelimitedCodec::new());
    transport.send(bytes.clone()).await.unwrap();

    // Ensure the message gets passed to the channel.
    match rx.recv().await {
        Some(value) => assert_eq!(value, message),
        _ => assert!(false),
    }
}

#[tokio::test]
async fn control_messages_survive_bulk_flood() {
    // A slow peer: accepts every connection the sender opens and reads one
    // frame per millisecond on each. Counts the control frames and exits
    // once all five arrived.
    let address = "127.0.0.1:5300".parse::<SocketAddr>().unwrap();
    let handle = tokio::spawn(async move {
        let listener = TcpListener::bind(&address).await.unwrap();
        let (tx_frame, mut rx_frame) = channel::<Bytes>(100);
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let tx_frame = tx_frame.clone();
                tokio::spawn(async move {
                    let mut transport = Framed::new(socket, LengthDelimitedCodec::new());
                    while let Some(Ok(frame)) = transport.next().await {
                        let _ = tx_frame.send(frame.freeze()).await;
                        sleep(Duration::from_millis(1)).await;
                    }
                });
            }
        });
        let mut controls = 0usize;
        while let Some(frame) = rx_frame.recv().await {
            if &frame[..] == b"control" {
                controls += 1;
                if controls == 5 {
                    return controls;
                }
            }
        }
        controls
    });

    let (tx, rx) = channel(10_000);
    let mut sender = NetSender::new(rx);
    tokio::spawn(async move {
        sender.run().await;
    });

    // Flood the peer with bulk far beyond its bounded queue (the excess is
    // dropped), then send the control messages. With the old single shared
    // queue the controls would be dropped along with the flood; with the
    // two-class sender they take the unbounded lane and jump the queue.
    let bulk = Bytes::from(vec![0u8; 10_000]);
    for _ in 0..3_000 {
        tx.send(NetMessage(bulk.clone(), vec![address], MessageClass::Bulk))
            .await
            .unwrap();
    }
    for _ in 0..5 {
        tx.send(NetMessage(
            Bytes::from("control"),
            vec![address],
            MessageClass::Control,
        ))
        .await
        .unwrap();
    }

    let controls = tokio::time::timeout(Duration::from_secs(20), handle)
        .await
        .expect("control messages never arrived at the flooded peer")
        .unwrap();
    assert_eq!(controls, 5);
}
