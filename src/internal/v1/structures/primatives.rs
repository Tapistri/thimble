use chrono::TimeZone;
use chrono::{DateTime, Utc};
use rasn::AsnType;
use rasn::prelude::*;

#[derive(AsnType, Decode, Encode)]
#[rasn(value("0..18446744073709551615"))]
pub struct UTCTime(pub Integer);

impl UTCTime {
    pub fn get_time(&self) -> Result<DateTime<Utc>, ()> {
        let value: i64 = (&self.0).try_into().map_err(|_| ())?;
        Ok(Utc.timestamp_millis_opt(value).single().ok_or_else(|| ())?)
    }
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct ValidityPeriod {
    pub not_before: UTCTime,
    pub not_after: UTCTime,
}

impl ValidityPeriod {
    pub fn as_time_tuple(&self) -> Result<(DateTime<Utc>, DateTime<Utc>), ()> {
        Ok((self.not_before.get_time()?, self.not_after.get_time()?))
    }

    pub fn time_in_duration(&self, time: DateTime<Utc>) -> Result<bool, ()> {
        let times = self.as_time_tuple()?;
        Ok(times.0 <= time && time <= times.1)
    }
}
