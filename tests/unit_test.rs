use cvss_vulnerability_scores::{parse_cvss, get_rating, vulnerability_calculate_cvss};

#[test]
#[should_panic]
fn test_parse_cvss_panic() {
    parse_cvss("");
    parse_cvss("CVSS:1.2/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N");
    parse_cvss("CVSS:1.2/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:W asdfasd fasdf");
}

#[test]
fn test_parse_cvss() {
    parse_cvss("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N");
    parse_cvss("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:N");
}

#[test]
fn test_get_rating() {
    assert_eq!(get_rating(0.0), "None");
    assert_eq!(get_rating(0.09), "None");
    assert_eq!(get_rating(0.1), "Low");
    assert_eq!(get_rating(3.2), "Low");
    assert_eq!(get_rating(8.234), "High");
    assert_eq!(get_rating(9.69), "Critical");
    assert_eq!(get_rating(10.00), "Critical");
    assert_eq!(get_rating(-1.0), "Invalid Value");
    assert_eq!(get_rating(10.32), "Invalid Value");
}

#[test]
fn test_vulnerability_calculate_cvss() {
    let metric_medium = "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N";
    let metric_medium = vulnerability_calculate_cvss(metric_medium);

    assert_eq!(metric_medium, 6.4);
}