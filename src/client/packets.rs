use crate::crypto::AuthKey;
use crate::proto::{
    b64_std, fake_xuid, json_escape, now_secs, offline_uuid, put_u32_le, put_u32_be, put_var_u32,
    random_client_id,
};
use crate::config::Device;

use super::skin::flat_skin;

pub fn make_login_packet(
    host: &str,
    port: u16,
    name: &str,
    auth: &AuthKey,
    protocol: u32,
    dev: &Device,
) -> Vec<u8> {
    let uuid = offline_uuid(name);
    let chain_payload = make_chain(host, port, name, auth, &uuid, protocol);
    let self_id = offline_uuid(&format!("{}-self", name));
    let rand_id = random_client_id(name);

    let skin_data = b64_std(&flat_skin());
    let payload = format!(
        "{{\"CapeData\":\"\",\"CapeId\":\"\",\"ClientRandomId\":{},\"CurrentInputMode\":1,\"DefaultInputMode\":1,\"DeviceId\":\"{}\",\"DeviceModel\":\"{}\",\"DeviceOS\":{},\"GameVersion\":\"{}\",\"GuiScale\":0,\"LanguageCode\":\"{}\",\"SelfSignedId\":\"{}\",\"ServerAddress\":\"{}:{}\",\"SkinData\":\"{}\",\"SkinId\":\"{}\",\"ThirdPartyName\":\"{}\",\"ThirdPartyNameOnly\":false,\"UIProfile\":1}}",
        rand_id,
        dev.device_id,
        dev.device_model,
        dev.device_os,
        dev.game_version,
        dev.language,
        self_id,
        json_escape(host),
        port,
        skin_data,
        dev.skin_id,
        json_escape(name)
    );

    let mut body = Vec::new();
    put_u32_le(&mut body, chain_payload.len() as u32);
    body.extend_from_slice(chain_payload.as_bytes());

    let jwt = auth.jwt(&payload, false);
    put_u32_le(&mut body, jwt.len() as u32);
    body.extend_from_slice(jwt.as_bytes());

    let mut pkt = Vec::new();
    pkt.push(0x01);
    put_u32_be(&mut pkt, protocol);
    pkt.push(0);
    put_var_u32(&mut pkt, body.len() as u32);
    pkt.extend_from_slice(&body);
    pkt
}

fn make_chain(host: &str, port: u16, name: &str, auth: &AuthKey, uuid: &str, _protocol: u32) -> String {
    let now = now_secs() as i64;
    let xuid = fake_xuid(name);
    let profile = format!(
        "{{\"certificateAuthority\":true,\"exp\":{},\"extraData\":{{\"XUID\":\"{}\",\"displayName\":\"{}\",\"identity\":\"{}\"}},\"identityPublicKey\":\"{}\",\"nbf\":{}}}",
        now + 86400,
        xuid,
        json_escape(name),
        uuid,
        auth.public_key_b64,
        now - 60
    );

    format!("{{\"chain\":[\"{}\"]}}", auth.jwt(&profile, false))
}