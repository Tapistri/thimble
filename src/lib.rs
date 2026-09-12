//! PUBLIC API RULES:
//! 1. Data passed in should be owned by the caller and be immutable.
//! 2. Data returned should be moved onto the heap where the caller is responsible for freeing it.
//! 3. Passed in pointers should be valid and tested to be non-null before dereferencing.

pub mod identity;
mod internal;
#[cfg(test)]
mod tests {}

// struct ImmutableBuffer {
//     data: *const u8,
//     len: usize,
// }

// impl ImmutableBuffer {
//     /// Create a ImmutableBuffer from a raw pointer\
//     /// # SAFETY: data must be valid for `len` bytes, and the `data` pointer must be aligned and nonull.
//     pub unsafe fn from_raw(len: usize, data: *const u8) -> Self {
//         ImmutableBuffer { data, len }
//     }

//     pub fn as_slice(&self) -> &[u8] {
//         if (self.len == 0) {
//             return &[];
//         }
//         unsafe { std::slice::from_raw_parts(self.data, self.len) }
//     }

//     pub fn to_vec(&self) -> Vec<u8> {
//         self.as_slice().to_vec()
//     }
// }

// #[repr(C)]
// struct CBuffer {
//     data: *mut u8,
//     size: usize,
// }

// impl CBuffer {
//     pub fn from_vec(vec: Vec<u8>) -> Self {
//         CBuffer {
//             data: Box::into_raw(vec.into_boxed_slice()) as *mut u8,
//             size: vec.len(),
//         }
//     }

//     pub fn move_to_heap(self) -> *mut Self {
//         Box::into_raw(Box::new(self))
//     }
// }

// #[unsafe(no_mangle)]
// pub extern "C" fn test() {
//     println!("Hello from rust!")
// }

// #[repr(C)]
// pub struct Bytes {
//     data: *mut u8,
//     len: usize,
// }

// #[repr(C)]
// pub enum ResultCode {
//     Ok,
//     GenericErr,
//     InvalidArgs,
//     NotYetImplemented,
// }

// #[repr(C)]
// union APIResultContent<R, E> {
//     ok: R,
//     err: E,
// }

// /// Holds a result from an call to the API
// /// When ResultCode != Ok, content the corresponding error type.
// #[repr(C)]
// pub struct APIResult<R, E> {
//     pub code: ResultCode,
//     pub reserved: u32, // force content to be 8-byte aligned always
//     pub content: APIResultContent<R, E>,
// }

// impl<T, E> APIResult<T, E> {
//     pub fn ok(content: T) -> Self {
//         Self {
//             code: ResultCode::Ok,
//             content: APIResultContent { ok: content },
//         }
//     }

//     pub fn err(code: ResultCode, content: E) -> Self {
//         Self {
//             code,
//             content: APIResultContent { err: content },
//         }
//     }

//     pub fn move_to_heap(self) -> *mut Self {
//         let boxed = Box::new(self);
//         Box::into_raw(boxed)
//     }
// }

// #[repr(C)]
// pub struct Key {
//     /**
//     127 > is Key Encapsulation, 127 <= is Signing
//     */
//     pub key_data: CBuffer,
//     pub key_type: u8,
// }

// #[repr(C)]
// pub struct Identity {
//     pub public_key: CBuffer,
//     pub private_key: CBuffer,
//     pub certificate: CBuffer,
// }

// #[unsafe(no_mangle)]
// pub extern "C" fn sign_data(
//     data: ImmutableBuffer,
//     private_key: Key,
//     public_key: Key,
// ) -> *mut APIResult<CBuffer, ()> {
//     if private_key.key_data.data.is_null() {
//         return APIResult::err(ResultCode::InvalidArgs, ()).move_to_heap();
//     }
//     let type_index = private_key.key_type & 0x7F;
//     if private_key.key_type != public_key.key_type {
//         return APIResult::err(ResultCode::InvalidArgs, ()).move_to_heap();
//     }
//     if private_key.key_type >= 127 {
//         let algorithm: SignatureAlgorithm = match type_index.try_into() {
//             Ok(alg) => alg,
//             Err(_) => {
//                 return APIResult::err(ResultCode::InvalidArgs, ()).move_to_heap();
//             }
//         };
//         // KEM
//         let private_key = &mut private_key.key_data.as_slice().to_vec();
//         let public_key = public_key.key_data.as_slice();
//         let keypair = signing::Keypair::new_private(private_key.as_mut_slice(), public_key);
//         let key = signing::deserialize_signingkey(keypair, &algorithm);
//         return match key {
//             None => return APIResult::err(ResultCode::InvalidArgs, ()).move_to_heap(),
//             Some(key) => {
//                 let result = match key.sign(data.as_slice()) {
//                     Ok(sig) => APIResult::ok(CBuffer::from_vec(vec)),
//                     Err(_) => APIResult::err(ResultCode::GenericErr, ()),
//                 };
//                 result.move_to_heap()
//             }
//         };
//     } else {
//         return APIResult::err(ResultCode::NotYetImplemented, ()).move_to_heap();
//     }
// }

// #[unsafe(no_mangle)]
// pub extern "C" fn create_new_identity() -> *mut Identity {
//     return 0 as *mut Identity;
// }
