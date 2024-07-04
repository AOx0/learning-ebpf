use std::net::UdpSocket;

use bstr::ByteSlice;

fn main() {
    let udp = UdpSocket::bind("[::]:5000").unwrap();

    let mut buffer = [0; 2048];

    loop {
        if let Ok((n, addr)) = udp.recv_from(&mut buffer) {
            println!("From: {:?} Recv: {:?}", addr, &buffer[..n].as_bstr());

            let app_msg = b" desde Server B!!\n";
            let n = if n + app_msg.len() < buffer.len() && n > 0 {
                let new_size = n - 1 + app_msg.len();
                buffer[n - 1..new_size].copy_from_slice(app_msg.as_slice());
                new_size
            } else {
                n
            };

            udp.send_to(&buffer[..n], addr).unwrap();
        }
    }
}
