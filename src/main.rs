use cvss_vulnerability_scores::{vulnerability_calculate_cvss, get_rating};
use clap::{App, Arg};

fn main() {

    let args = App::new("cvss")
        .arg(Arg::with_name("cvss_vector")
        .takes_value(true)
        .required(true))
        .get_matches();

    let cvss_vector = args.value_of("cvss_vector").unwrap();    
    
    
    let base_score = vulnerability_calculate_cvss(cvss_vector);
    let rating = get_rating(base_score);

    println!("{} which is {}", base_score, rating);
}