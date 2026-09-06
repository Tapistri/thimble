mod identity;
mod internal;
#[cfg(test)]
mod tests {}

#[unsafe(no_mangle)]
pub extern "C" fn test() {
    println!("Hello from rust!")
}
