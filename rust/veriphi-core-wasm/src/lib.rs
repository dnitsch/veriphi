use js_sys::Error as JsError;
use js_sys::{Array, BigInt, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_rayon::init_thread_pool;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen::JsCast;
use std::convert::TryInto;


use veriphi_core::utils;
use veriphi_core::involute;
use veriphi_core::encrypt;
use veriphi_core::decrypt;

#[wasm_bindgen(js_name = initThreads)]
pub async fn init_threads(threads: usize) -> Result<(), JsValue> {
    let p = init_thread_pool(threads);
    JsFuture::from(p).await?;
    Ok(())
}

#[wasm_bindgen(start)]
pub fn _init_panic_hook() {
    console_error_panic_hook::set_once(); // if you add the crate
}

#[wasm_bindgen(js_name = getChunkSize)]
pub fn get_chunk_size(packet: &[u8]) -> usize {
    return involute::get_chunk_size(packet);
}

#[wasm_bindgen(js_name = getChunkSizeMin)]
pub fn get_chunk_size_min(packet: &[u8], min_size: usize) -> usize {
    return involute::get_chunk_size_min(packet, min_size);
}

#[wasm_bindgen(js_name = involutePacket)]
pub fn involute_packet(packet: &[u8], salt: &[u8], chunk_size: usize) -> Result<Vec<u8>, JsValue> {
    let result = involute::involute_packet(&packet, &salt, chunk_size)
        .map_err::<JsValue, _>(|e| JsError::new(&format!("Involute error: {e}")).into())?;
    return Ok(result);
}

#[wasm_bindgen(js_name = cyclePacket)]
pub fn cycle_packet(
    packet: &[u8],
    old_salt: &[u8],
    new_salt: &[u8],
    old_key: &[u8],
    new_key: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, JsValue> {
    let cycled = involute::cycle_packet(
        &packet, &old_salt, &new_salt, &old_key, &new_key, chunk_size,
    )
    .map_err::<JsValue, _>(|e| JsError::new(&format!("Cycle error: {e}")).into())?;
    return Ok(cycled);
}

#[wasm_bindgen(js_name = genKey)]
pub fn gen_key(party_id: String, purpose: String, master_seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    if master_seed.len() != 32 {
        return Err(JsError::new("Master seed must be 32 bytes").into());
    }
    let seed_array: &[u8; 32] = master_seed
        .as_ref()
        .try_into()
        .expect("Already checked length");

    let key = utils::gen_key(&party_id, &purpose, seed_array).to_vec();
    return Ok(key);
}

#[wasm_bindgen(js_name = condInvolutePacket)]
pub fn cond_involute_packet(
    packet: &[u8],
    involute_salt: &[u8],
    chunk_size: usize,
    low_bound: u64,
    high_bound: u64,
    test_value: f32,
) -> Result<Vec<u8>, JsValue> {
    let involuted = involute::cond_involute_packet(
        &packet,
        &involute_salt,
        chunk_size,
        low_bound,
        high_bound,
        test_value,
    )
    .map_err::<JsValue, _>(|e| JsError::new(&format!("Involute error: {e}")).into())?;
    return Ok(involuted);
}

#[wasm_bindgen(js_name = condHashBranch)]
pub fn cond_hash_branch(
    low_bound: u64,
    high_bound: u64,
    test_value: f32,
    salt: &[u8],
) -> Result<u64, JsValue> {
    let condition = involute::cond_hash_branch(low_bound, high_bound, test_value, salt);
    return Ok(condition);
}

#[wasm_bindgen(js_name = prepCondition)]
pub fn prep_condition(low_bound: f32, high_bound: f32, salt: &[u8]) -> Result<Array, JsValue> {
    let (low_embed, high_embed) = involute::prep_condition(low_bound, high_bound, salt);
    let out = Array::new();
    out.push(&BigInt::from(low_embed).into());
    out.push(&BigInt::from(high_embed).into());
    return Ok(out);
}


#[wasm_bindgen(js_name = mapData)]
pub fn map_data(
    pub_key: &[u8],
    priv_key: &[u8],
    identity: usize,
    data_sequences: Array,
) -> Result<Vec<u8>, JsValue> {
    let mut rust_data: Vec<Vec<u8>> = Vec::with_capacity(data_sequences.length() as usize);
    for v in data_sequences.iter() {
        let u8a = Uint8Array::from(v);
        rust_data.push(u8a.to_vec());
    }

    let output = encrypt::map_data(&pub_key, &priv_key, identity, rust_data);
    return Ok(output);
}

#[wasm_bindgen(js_name = invData)]
pub fn inv_data(pub_key: &[u8], priv_keys: Array, data_sequences: Array) -> Result<Array, JsValue> {
    let rust_priv: Vec<Vec<u8>> = priv_keys
        .iter()
        .map(|v| Uint8Array::from(v).to_vec())
        .collect();
    let rust_data: Vec<Vec<u8>> = data_sequences
        .iter()
        .map(|v| Uint8Array::from(v).to_vec())
        .collect();

    let size = 1 << 8;
    let output = decrypt::inv_data(&pub_key, &rust_priv, rust_data, size as usize);
    let out = Array::new();
    for v in output {
        out.push(&Uint8Array::from(&v[..]));
    }
    return Ok(out);
}

fn js_value_to_field(value: &JsValue) -> Result<utils::PackageField<'static>, JsValue> {
    if value.is_instance_of::<Uint8Array>() {
        let arr = Uint8Array::new(value);
        return Ok(utils::PackageField::from(arr.to_vec()));
    }

    if let Some(text) = value.as_string() {
        return Ok(utils::PackageField::from(text.into_bytes()));
    }

    if value.is_instance_of::<BigInt>() {
        let bigint: BigInt = value.clone().dyn_into().map_err(|_| JsError::new("Failed to interpret value as BigInt"))?;
        let s_js = bigint
            .to_string(10)
            .map_err(|_| JsError::new("Failed to convert BigInt to string"))?;
        let s: String = s_js.into();
        let parsed = s
            .parse::<u64>()
            .map_err(|_| JsError::new("BigInt value out of u64 range"))?;
        return Ok(utils::PackageField::from(parsed));
    }

    if let Some(num) = value.as_f64() {
        if num < 0.0 || num.fract() != 0.0 {
            return Err(JsError::new("Numeric identity must be a non-negative integer").into());
        }
        if num > (u64::MAX as f64) {
            return Err(JsError::new("Numeric identity exceeds u64 range").into());
        }
        return Ok(utils::PackageField::from(num as u64));
    }

    Err(JsError::new("Unsupported field type for packageBlob").into())
}

#[wasm_bindgen(js_name = packageBlob)]
pub fn package_blob(fields: Array) -> Result<Vec<u8>, JsValue> {
    let mut items: Vec<utils::PackageField<'static>> =
        Vec::with_capacity(fields.length() as usize);
    for value in fields.iter() {
        items.push(js_value_to_field(&value)?);
    }
    Ok(utils::package_blob(items))
}
