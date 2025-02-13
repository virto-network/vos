/// All sensors available in the system
pub enum OsSensor {
    // Std(super::std_ports::Sensor),
}

impl super::Sensor for OsSensor {
    async fn ready(&self) -> super::Datum {
        todo!()
    }
}
