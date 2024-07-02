use libc::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlFamily, GenlMessage,
};
use netlink_packet_wireguard::{nlas::WgDeviceAttrs, Wireguard, WireguardCmd};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};

fn socket_send<Message>(
    socket: &mut Socket,
    packet: &NetlinkMessage<Message>,
) -> std::io::Result<usize>
where
    Message: NetlinkSerializable + std::fmt::Debug,
{
    let packet = &packet;

    log::debug!("<- {packet:?}");

    let mut buf = vec![0u8; packet.header.length as usize].into_boxed_slice();
    assert_eq!(buf.len(), packet.buffer_len());

    packet.serialize(&mut buf);

    log::trace!("<- {buf:?}");
    socket.send(&buf, 0)
}

fn socket_recv<Message>(socket: &mut Socket) -> std::io::Result<Vec<Message>>
where
    Message: NetlinkDeserializable + Clone + std::fmt::Debug,
{
    let mut buf = vec![0u8; 4096];
    let mut offset = 0;
    let mut messages = Vec::new();

    loop {
        let (len, _) = socket.recv_from(&mut &mut buf[..], 0)?;
        let buf = &buf[..len];

        log::trace!("-> {buf:?}");

        loop {
            let buf = &buf[offset..];

            let packet = NetlinkMessage::<Message>::deserialize(buf).unwrap();

            log::debug!("-> {packet:?}");

            match packet.payload {
                NetlinkPayload::Done(_) => return Ok(messages),
                NetlinkPayload::InnerMessage(message) => {
                    messages.push(message.clone());
                }
                NetlinkPayload::Error(err) => {
                    return match err.code {
                        Some(_) => Err(err.into()),
                        None => Ok(messages),
                    };
                }
                _ => {}
            }

            offset += packet.header.length as usize;
            if offset == len || packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}

#[derive(clap::Parser)]
struct Args {
    interface: String,
}

async fn real_main() {
    env_logger::init();

    let Args { interface } = clap::Parser::parse();

    let mut generic = Socket::new(NETLINK_GENERIC).unwrap();

    let mut addr = SocketAddr::new(0, 0);
    generic.bind(&addr).unwrap();
    generic.get_address(&mut addr).unwrap();

    let mut message = NetlinkMessage::from(GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(
            Wireguard::family_name().to_owned(),
        )],
    }));
    message.header.flags = (NLM_F_REQUEST | NLM_F_ACK) as _;
    message.finalize();

    socket_send(&mut generic, &message).unwrap();

    let messages = socket_recv::<GenlMessage<GenlCtrl>>(&mut generic).unwrap();

    let family_id = messages
        .into_iter()
        .flat_map(|msg| msg.payload.nlas.into_iter())
        .find_map(|attr| match attr {
            GenlCtrlAttrs::FamilyId(id) => Some(id),
            _ => None,
        });

    let family_id = family_id.unwrap();

    let mut message = NetlinkMessage::from(GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(interface.clone())],
    }));
    message.header.flags = (NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP) as _;
    let NetlinkPayload::InnerMessage(ref mut payload) = message.payload else {
        panic!();
    };
    payload.set_resolved_family_id(family_id);
    message.finalize();

    socket_send(&mut generic, &message).unwrap();

    let messages = socket_recv::<GenlMessage<Wireguard>>(&mut generic).unwrap();

    log::info!("{messages:?}");
}

fn main() {
    let ex = async_executor::LocalExecutor::new();
    let task = ex.spawn(real_main());
    async_io::block_on(ex.run(task));
}
