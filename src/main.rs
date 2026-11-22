//! SigmaOS component binary: sec-audit

use sigmaos_sec-audit::Component;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Component::new().operate()?;
    println!("sigmaos-sec-audit: ok");
    Ok(())
}
