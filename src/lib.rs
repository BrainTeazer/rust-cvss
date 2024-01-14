use regex::{Regex, Captures};
use core::panic;
use std::collections::HashMap;
use itertools::Itertools;

pub struct Metrics {
    pub av: f64, // Access Vector
    pub ac: f64, // Access Complexity
    pub pr: f64, 
    pub ui: f64, 
    pub c: f64, // Confidentiality
    pub i: f64, // Integrity
    pub a: f64, // Availability
    pub sc: bool // Scope ( true === changed, false === unchanged)
} 

//
// TODO: ERROR HANDLING and TEST CASES
//
pub fn get_qualitative_metrics<'a>(is_changed:bool) -> HashMap<&'a str, HashMap< &'a str, f64>> {
    let mut qualitative_metric = HashMap::new();

    if is_changed {
        qualitative_metric.insert(
            "PR", 
            HashMap::from([("N", 0.85), ("L", 0.68), ("H", 0.27)])
        );  
    } else {
        qualitative_metric.insert( 
            "PR", 
            HashMap::from([("N", 0.85), ("L", 0.62), ("H", 0.27)])
        );
    }
   
    
    qualitative_metric.insert( 
        "AV", 
        HashMap::from([("N", 0.20), ("A", 0.62), ("L", 0.55), ("P", 0.20)])
    );

    qualitative_metric.insert( 
        "AC", 
        HashMap::from([("L", 0.77), ("H", 0.44)])
    );
    

    qualitative_metric.insert( 
        "UI", 
        HashMap::from([("N", 0.85), ("R", 0.62)])
    );

    qualitative_metric.insert( 
        "C", 
        HashMap::from([("H", 0.56), ("L", 0.22), ("N", 0.00)])
    );

    qualitative_metric.insert( 
        "I", 
        HashMap::from([("H", 0.56), ("L", 0.22), ("N", 0.00)])
    );

    qualitative_metric.insert( 
        "A", 
        HashMap::from([("H", 0.56), ("L", 0.22), ("N", 0.00)])
    );

    qualitative_metric
}

pub fn parse_cvss(cvss_vector: &str) -> Captures{
    let get_base_score_metric = r"CVSS:3\.1/(AV):([NALP])/(AC):([LH])/(PR):([NLH])/(UI):([NR])/S:[UC]/(C):([NLH])/(I):([NLH])/(A):([NLH])";
    let regex = Regex::new(get_base_score_metric);
    

    let re = match regex {
        Ok(re) => re,
        Err(e) => panic!("Invalid regex! Error {}", e)
    };
  
    return match re.captures(cvss_vector) {
   
        Some(re) =>  re ,
        None => panic!("Invalid CVSS vector!")
    };

}

pub fn parse_scope(cvss_vector: &str) -> bool {
    let get_scope = r"S:([UC])";
    let regex = Regex::new(get_scope);

    let re = match regex {
        Ok(re) => re,
        Err(e) => panic!("Invalid regex! Error {}", e)
    };

    let scope = re.captures(cvss_vector);

    // if value is captured check its value and return true or false correspondingly  
    match scope {
        Some(scope) => {
            scope.get(1).map_or("", |m| m.as_str()).eq("C")
        },
        None => panic!("Scope not provided or valid")
    }
}

pub fn vulnerability_calculate(metrics: Metrics) -> f64 {


    let iss = 1.0 - (1.0 - metrics.c) * (1.0 - metrics.i) * (1.0 - metrics.a);
    let exp = 8.22 * metrics.av * metrics.ac * metrics.pr * metrics.ui;
    let mut imp = 6.42 * iss;
    let bs;
    
    if metrics.sc {
        imp = 7.52 * (iss - 0.029) - 3.25 * f64::powi(iss - 0.02, 15);
    }


    if imp <= 0.0 {
        bs = 0.0;
    }
    else if metrics.sc {
        bs = f64::min(1.08*imp + exp, 10.0);
    }
    else {
        bs = f64::min(imp + exp, 10.0);
    }
    
    ( bs * 10.0 ).ceil() / 10.0
}

pub fn vulnerability_calculate_cvss(cvss_vector: &str) -> f64 {
    let is_changed = parse_scope(cvss_vector);
    let qualitative_metric = get_qualitative_metrics(is_changed);

    let caps = parse_cvss(cvss_vector);

    let mut cvss = HashMap::new();


    for (m, v) in caps.iter().skip(1).tuples() {
        let metric = match m {
            Some(met) => met.as_str(),
            None => panic!("Error.")
        };

        let value = match v {
            Some(val) => val.as_str(),
            None => panic!("Error.")
        };

        let num_val = *(qualitative_metric.get(metric).unwrap().get(value).unwrap());
        cvss.insert(metric, (value, num_val));
        
    }

    let metrics = Metrics {
        av: cvss.get("AV").unwrap().1,
        ac: cvss.get("AC").unwrap().1,
        pr: cvss.get("PR").unwrap().1,
        ui: cvss.get("UI").unwrap().1,
        c: cvss.get("C").unwrap().1,
        i: cvss.get("I").unwrap().1,
        a: cvss.get("A").unwrap().1,
        sc: is_changed,
    };

    vulnerability_calculate(metrics)
}

trait InRange {
    fn in_range(self, begin:Self, end:Self)->bool;
    fn in_range_inclusive(self, begin:Self, end:Self)->bool;
}

impl InRange for f64 {
    fn in_range(self, begin:Self, end:Self)->bool {
        self >= begin && self < end
    }

    fn in_range_inclusive(self, begin:Self, end:Self)->bool {
        self >= begin && self <= end
    }
}

pub fn get_rating<'a> (val: f64) -> &'a str {
    match val  {
        x if x.in_range(0.0, 0.1) => "None",
        x if x.in_range(0.1, 4.0) => "Low",
        x if x.in_range(4.0, 7.0 )=> "Medium",
        x if x.in_range(7.0, 9.0) => "High",
        x if x.in_range_inclusive(9.0, 10.0) => "Critical",
        _ => "Invalid Value"
    }
}


