// SPDX-License-Identifier: AGPL-3.0-only

//! P04 slice 9: a separately hosted input page derives its expiry countdown
//! from the controller's clock, so an allowed browser origin must be able to
//! read the response `Date` header. Nothing else is newly exposed.

mod support;

use support::{Harness, ORIGIN};

fn header<'a>(response: &'a support::HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn allowed_origin_can_read_the_controller_date() {
    let harness = Harness::start_with(&[("BLINDPASS_CORS_ALLOWED_ORIGINS", ORIGIN)]).await;
    let response = harness
        .request(
            "GET",
            "/api/v2/secret/metadata/00000000-0000-4000-8000-000000000000?sig=1.invalid",
            &[("origin", ORIGIN)],
            None,
        )
        .await;
    assert_eq!(
        header(&response, "access-control-allow-origin"),
        Some(ORIGIN)
    );
    assert!(header(&response, "date").is_some(), "controller sends Date");
    let exposed = header(&response, "access-control-expose-headers")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let exposed: Vec<&str> = exposed.split(',').map(str::trim).collect();
    assert_eq!(exposed, vec!["date"], "only Date is exposed");
}

#[tokio::test]
async fn other_origins_still_get_no_cors_grant() {
    let harness = Harness::start_with(&[("BLINDPASS_CORS_ALLOWED_ORIGINS", ORIGIN)]).await;
    let response = harness
        .request(
            "GET",
            "/api/v2/secret/metadata/00000000-0000-4000-8000-000000000000?sig=1.invalid",
            &[("origin", "https://attacker.example")],
            None,
        )
        .await;
    // tower-http still sends the static expose/credentials headers here;
    // without an Allow-Origin grant a browser ignores them.
    assert_eq!(header(&response, "access-control-allow-origin"), None);
}
