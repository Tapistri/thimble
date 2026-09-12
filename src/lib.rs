//! PUBLIC API RULES:
//! 1. Data passed in should be owned by the caller and be immutable.
//! 2. Data returned should be moved onto the heap where the caller is responsible for freeing it.
//! 3. Passed in pointers should be valid and tested to be non-null before dereferencing.

pub mod identity;
mod internal;
#[cfg(test)]
mod tests {}
