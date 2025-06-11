use sev_snp::SevSnp;

fn main() {
    // Initialise an SevSnp object
    let sev_snp = SevSnp::new().unwrap();

    // Retrieve the derived key
    let dev_key = sev_snp.get_derived_key().unwrap();
    println!("Derived key: {:?}", dev_key);
}
