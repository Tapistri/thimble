use rand::{SeedableRng, TryRng};

pub fn random_bytes(buffer: &mut [u8]) -> Result<(), ()> {
    let mut rng = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).map_err(|e| ())?;
    rng.try_fill_bytes(buffer).map_err(|e| ())?;
    Ok(())
}
