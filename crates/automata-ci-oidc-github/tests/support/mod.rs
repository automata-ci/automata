#![allow(dead_code)]

use std::sync::Arc;

use automata_ci_oidc_github::{
    AuthorizedOidcAuthority, InMemoryOidcRepository, InMemoryOidcRepositoryLimits, OidcAudience,
    OidcAuthorityId, OidcClaimSet, OidcIdToken, OidcIssuanceRepository, OidcIssuer, OidcKeyId,
    OidcRequestBearer, OidcService, OidcSubject, OidcSupportedClaims, OidcTokenLifetime,
    RequestBearerConfig, RequestBearerKey, RequestBearerKeyring, Rs256Keyring, Rs256SigningKey,
    RsaPublicJwk,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

pub(crate) const NOW_SECONDS: u64 = 1_800_000_000;
pub(crate) const TEST_KEY_ID: &str = "test-rs256-2026-08";
pub(crate) const TEST_REPLACEMENT_KEY_ID: &str = "test-rs256-2026-09";
pub(crate) const TEST_RSA_MODULUS: &str = "3EB2d40ghnbyGr9du8XI5MMt_dHBRJlGaIQzk_fgMxwAxiToz5Ck540SPVcosHkRC-YjGIXjhwDSOlSJ9kxsoQRM5venRhsZeQWeuo_82S95k6CFguafVLvOSmFKltf5obDHo6DBxum_C_1jc4ZTJGEi1K7AV33qhJ_qZfAMI8K8a6xIpkXtcpTDU-yxTrdFQF5yzW7cVqyoXjHbcxIIS2UMVZTMJ3Hv5pgDxe9eYhVlxkBO0oZn89jVVMSfKnThlsj02cd9N5doFuJEKB5NTYGG9E7uWnOEq_jddN-NNa8hU1PTSqpzwIdDs1ZBet2wmNl5Wr1KI981Rkp2FTvPkw";
pub(crate) const TEST_REPLACEMENT_RSA_MODULUS: &str = "o1A6wARhTiKLU_SKTdxcBDZK2gGqMoFS-fLEh_4fL-14V0JW5xRjwbzAO8m3oqzjCT9sDU1AZh-czgZ7QQQ8njEYrVykYLkapZOffcQvFt7rzsc2C9pbrkOnmbBq0b3_U53NPM1Fy1B3s1C_CRuOP7urc0VELeFaaEy3JFMTUpZDC-sti-JzY768ZfgwrcWkp703jEl2N7kkUoBQPZjpyymfm4ABPQJ6gObx95gAmV3p4XBIYxaxhoh7oSLUyF4solYC7N3mDCHmdf2CIbb8INdMfiqhLqOafdm9qCHT4wDNya94v7U7pHiggHyIkSa3RfMWomjDIEY39LSDgaFYSw";
pub(crate) const TEST_RSA_EXPONENT: &str = "AQAB";
const TEST_PRIVATE_KEY_BODY: &str = r"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDcQHZ3jSCGdvIa
v127xcjkwy390cFEmUZohDOT9+AzHADGJOjPkKTnjRI9VyiweREL5iMYheOHANI6
VIn2TGyhBEzm96dGGxl5BZ66j/zZL3mToIWC5p9Uu85KYUqW1/mhsMejoMHG6b8L
/WNzhlMkYSLUrsBXfeqEn+pl8AwjwrxrrEimRe1ylMNT7LFOt0VAXnLNbtxWrKhe
MdtzEghLZQxVlMwnce/mmAPF715iFWXGQE7Shmfz2NVUxJ8qdOGWyPTZx303l2gW
4kQoHk1NgYb0Tu5ac4Sr+N103401ryFTU9NKqnPAh0OzVkF63bCY2XlavUoj3zVG
SnYVO8+TAgMBAAECggEAWtLWR0xR+kD4ayE4tOLFidgWkhE6AmC2UQka/8x6jnjg
tNSpkFZUOgvJVrQnWkZCSkbXeBhWD+i9yEHuNjujm+5bC+9Z8iXgpjA0GTihCqpy
FvddtvIFB/r+AVwHVxauoQd1+7qhzbW8C2Ss6wmcJWdM5qk9NZb96zzKesi3KNMz
t0zGmdm8frIppxnP2U/S5+Tu/3uHdG7TqJdFWX1qx6FKSi3oQdSrhKhCzCxEZO/A
slb9OJZPvPBAO9/BIJQiMPgLq1cIAj8q1uK8DAYIbYFNkzpVNYyVBk1E2KSJxUCg
zC3QgJ1XzHcEpDTAmv1o+yYAX58+DgAM0jvJYnp3cQKBgQD4hWRMC4c2L7lkP+fy
VHl6jNXKLSzonlOlVqJnz+D4EJI94hTHlkFLHKZKZLcKekokjtuohZuS7x9hZcIP
EVs5w+NPOIfhEk+s5UmRRxeojl86f1TrLhvkUqvkwPSuWR0zmNyEzh1OYNdoEM/G
CzxOzhczp6mOuH7A2CFnS8dhSwKBgQDi4UjP0i+BEE3nE02+QaPqP4N6Z5sXQKq0
IJtcBjZMm79g8TN5ZYWBpFlhNCOHn+AxYvh5tPq+QM9XuQQDHzxum5CRCFVWSCDu
IMR7dNs3Y3gXnPY4G5siCAWj/TuLs+GG/6iMezoE3+4j19zHxQRrYfGJQMOYlgMw
LT9jeG+l2QKBgCinoaWzCRZ7LifRMH97BDhhC6Q8SalwJRzaFE1JO3M5OsM21dFk
qh/Aew+WdD8ZjEF4wURLPw0FYyvKurk+TJ8hhXDzPX87QJ93DtbeO2eOitOF+v1S
GKv8PjR4wE45M8a6DfEHytGElBhpD6RFOENoAXGoztsTIWEouiYsxlwLAoGBAKpj
rS4+2WRhnVAUpEdlvrfXOWP9WXGuJEWhU2xaUf9Y3PLuUs0yHIEPr/ybjq91t4b/
oEKvU7z8qXtlPQknNViQRpNVodlp1ClivI1HZreDYZbCT/w1Z124jpvpPAYgcxjS
+n9+sEUm9A9BN9NkOHx5E1AULpFy4DQXV0raEWeJAoGBAJN+ZF4n+c+pzlUObvtC
H3N4m86U0TUSWCXJe4Kv/5eNdkdjztyUJ8diHOK530A0wWAc7zK9L2NJh/qHC+cY
XTlo/WPBMPJ3JOYlcxCXVn4sCBlRlPIccmoS6vGKQiWadCgwxLaBZNWctfKOQAdm
tPlzul2Px6cR3krgeRjgAs0j";
const TEST_REPLACEMENT_PRIVATE_KEY_BODY: &str = r"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCjUDrABGFOIotT
9IpN3FwENkraAaoygVL58sSH/h8v7XhXQlbnFGPBvMA7ybeirOMJP2wNTUBmH5zO
BntBBDyeMRitXKRguRqlk599xC8W3uvOxzYL2luuQ6eZsGrRvf9Tnc08zUXLUHez
UL8JG44/u6tzRUQt4VpoTLckUxNSlkML6y2L4nNjvrxl+DCtxaSnvTeMSXY3uSRS
gFA9mOnLKZ+bgAE9AnqA5vH3mACZXenhcEhjFrGGiHuhItTIXiyiVgLs3eYMIeZ1
/YIhtvwg10x+KqEuo5p92b2oIdPjAM3Jr3i/tTukeKCAfIiRJrdF8xaiaMMgRjf0
tIOBoVhLAgMBAAECggEARw+faLLfNjTwxCi5T1TNkyWen0qvKIe+N7UrT/NC1cNy
JCHhF253U7MSQFGu/nFU3s7CcO1G0sj5nWoTkoBJ8hlx3+laOx4AGsDn2r0VMlHw
cEqdWT37u5GDqWuqpzYRlewphEXbkzKhyxwc69UaKeA6o48lsgMHKDANVphxZXL7
nliHUI/ysmHQWsgBcxBS8xUYJr0ZzYI/7ytqa9jn36lQBbwQ+U91MOXvkBtiVzlY
OWwZ4UNKUb1XkcGgWvu1aVBhsL3FXFc0Yt9nEVX0zTKKzsb2b8DnbWot0vKWsbHK
dS9oUUnlKrc8NAfiFpsg6YZWZL7AAc0sUMkFqaGKwQKBgQDRcRz48iGkmB+dHzx/
clbwRa+hFK1KXINVjG5p0g6wuY5tEtF2C8LtPhl0ybHALr78RZFBYCC/oc/L8t1a
zhCeUXdAR8OTwT6JFLgWdqd9P9wFHnV7V/fP9rtaCweCMGVo+82Q/tHXufvIgpgm
YgRYosEUa/Tqk2ETKTrCpDyxCwKBgQDHnguCfbAZSkuKsV3GT2U5eejlRo0yZlSO
KkQ2Weolvp+PBrQqhZlkRs0JNe8+KYePkdc25ue/IsC6I2xAs6x9ywVl/njGVy6R
2MvZ4BkT3lf5M5YhJDoelDqiSGTo711/qhY6rdvpor8tar6+zFCsmV86UwaeCUA+
cFFGf7j9wQKBgB/YkCw2PPFXBC+S6VMDor6EChF3IGZXLM0cPkmu2/b5L/Pb0aee
YDRMpfhBFtr/AKFBPrXvFOuugfcj5Y6CGLrJ7lUC1HUqBAU59kfMIOmFhUHuALUR
iie//3rQhILCMxlEeFxcsrGXoPY7DUGA0+JaVPty8tmcMT2Fnl6sNGJDAoGAQGI3
cCU98UpHRzqh9l6RVZJ+jcTNsd3Tk+8KBUXHAdmT+Tu+TKC+stsrMrdUrQYUFTiC
49BiGwIIi4D1X4EUN5aN7THAnqhr+tqkFWf0brYeReBfodzfahGBP+p9savSymR/
uvlsntTBONLfJwcbVjA5yMQStFJjiEAN1uFHN4ECgYAPJdJvC9DZiPYzW8XLq/yJ
DZ9/Oee47TlmWCu6u19WYhCptY0H684HBeOnFo7/idKicNUqnHicN9XTcq5E8j5f
glu2nlK2QMPKwi98A22Yj/CtYjB8ldL/jg5rG1N/lmj9fGC7P7or9Ucsc4w0j27M
norlX3KEHNe7cTke5cP4OA==";

pub(crate) fn private_key_pem() -> String {
    let label = ["PRIVATE", "KEY"].join(" ");
    format!("-----BEGIN {label}-----\n{TEST_PRIVATE_KEY_BODY}\n-----END {label}-----\n")
}

fn replacement_private_key_pem() -> String {
    let label = ["PRIVATE", "KEY"].join(" ");
    format!("-----BEGIN {label}-----\n{TEST_REPLACEMENT_PRIVATE_KEY_BODY}\n-----END {label}-----\n")
}

pub(crate) fn authority_id() -> OidcAuthorityId {
    OidcAuthorityId::from_uuid(
        Uuid::parse_str("8f95d099-7317-461c-a9fc-4c97810ddcb9").expect("authority UUID"),
    )
    .expect("authority ID")
}

pub(crate) fn public_jwk() -> RsaPublicJwk {
    RsaPublicJwk::new(
        OidcKeyId::new(TEST_KEY_ID).expect("key ID"),
        TEST_RSA_MODULUS,
        TEST_RSA_EXPONENT,
    )
    .expect("public JWK")
}

pub(crate) fn signing_keyring() -> Arc<Rs256Keyring> {
    let private_key_pem = private_key_pem();
    let signing_key =
        Rs256SigningKey::from_pem(&private_key_pem, public_jwk()).expect("signing key");
    Arc::new(
        Rs256Keyring::new(
            OidcKeyId::new(TEST_KEY_ID).expect("active key ID"),
            [signing_key],
        )
        .expect("signing keyring"),
    )
}

pub(crate) fn prepublished_signing_keyring(active_key_id: &str) -> Arc<Rs256Keyring> {
    let private_key_pem = private_key_pem();
    let old_key = Rs256SigningKey::from_pem(
        &private_key_pem,
        RsaPublicJwk::new(
            OidcKeyId::new(TEST_KEY_ID).expect("old key ID"),
            TEST_RSA_MODULUS,
            TEST_RSA_EXPONENT,
        )
        .expect("old public JWK"),
    )
    .expect("old signing key");
    let replacement_private_key_pem = replacement_private_key_pem();
    let replacement_key = Rs256SigningKey::from_pem(
        &replacement_private_key_pem,
        RsaPublicJwk::new(
            OidcKeyId::new(TEST_REPLACEMENT_KEY_ID).expect("replacement key ID"),
            TEST_REPLACEMENT_RSA_MODULUS,
            TEST_RSA_EXPONENT,
        )
        .expect("replacement public JWK"),
    )
    .expect("replacement signing key");
    Arc::new(
        Rs256Keyring::new(
            OidcKeyId::new(active_key_id).expect("active key ID"),
            [replacement_key, old_key],
        )
        .expect("prepublished signing keyring"),
    )
}

pub(crate) fn request_keyring() -> Arc<RequestBearerKeyring> {
    let key_id = OidcKeyId::new("test-request-2026-08").expect("request key ID");
    let key = RequestBearerKey::new(
        key_id.clone(),
        b"synthetic-test-only-request-bearer-key-material-2026-08",
    )
    .expect("request key");
    Arc::new(
        RequestBearerKeyring::new(
            RequestBearerConfig::new(
                "automata-ci-oidc-request/v1",
                "automata-ci-oidc-mint/v1",
                3_600,
                30,
            )
            .expect("request policy"),
            key_id,
            [key],
        )
        .expect("request keyring"),
    )
}

pub(crate) fn authorized_authority() -> AuthorizedOidcAuthority {
    AuthorizedOidcAuthority::new(
        authority_id(),
        OidcSubject::new("repo:example/project:ref:refs/heads/main").expect("subject"),
        OidcAudience::new("https://example.invalid/owner").expect("default audience"),
        OidcClaimSet::new([
            ("ref".to_owned(), "refs/heads/main".to_owned()),
            ("repository_id".to_owned(), "123456".to_owned()),
        ])
        .expect("claims"),
        NOW_SECONDS - 60,
        NOW_SECONDS + 1_800,
    )
    .expect("authority")
}

pub(crate) fn configured_service() -> (
    Arc<OidcService>,
    Arc<InMemoryOidcRepository>,
    OidcRequestBearer,
) {
    configured_service_with_limits(InMemoryOidcRepositoryLimits::default())
}

pub(crate) fn configured_service_with_limits(
    limits: InMemoryOidcRepositoryLimits,
) -> (
    Arc<OidcService>,
    Arc<InMemoryOidcRepository>,
    OidcRequestBearer,
) {
    let repository = Arc::new(InMemoryOidcRepository::new(limits));
    repository
        .upsert_authority(authorized_authority())
        .expect("insert authority");
    let (service, bearer) = configured_service_with_repository(repository.clone());
    (service, repository, bearer)
}

pub(crate) fn configured_service_with_repository(
    repository: Arc<dyn OidcIssuanceRepository>,
) -> (Arc<OidcService>, OidcRequestBearer) {
    configured_service_with_repository_and_signing_keyring(repository, signing_keyring())
}

pub(crate) fn configured_service_with_repository_and_signing_keyring(
    repository: Arc<dyn OidcIssuanceRepository>,
    signing_keys: Arc<Rs256Keyring>,
) -> (Arc<OidcService>, OidcRequestBearer) {
    let request_keyring = request_keyring();
    let bearer = request_keyring
        .issue(authority_id(), NOW_SECONDS - 30, NOW_SECONDS + 900)
        .expect("request bearer");
    let service = Arc::new(OidcService::new(
        OidcIssuer::https(Url::parse("https://oidc.example.invalid/").expect("issuer URL"))
            .expect("issuer"),
        OidcSupportedClaims::new(["ref".to_owned(), "repository_id".to_owned()])
            .expect("supported claims"),
        OidcTokenLifetime::from_seconds(300).expect("token lifetime"),
        request_keyring,
        signing_keys,
        repository,
    ));
    (service, bearer)
}

pub(crate) fn decode_token(token: &OidcIdToken) -> (Value, Value) {
    let mut segments = token.expose_secret().split('.');
    let header = segments.next().expect("JWT header");
    let claims = segments.next().expect("JWT claims");
    let signature = segments.next().expect("JWT signature");
    assert!(!signature.is_empty());
    assert!(segments.next().is_none());
    (
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("decode header"))
            .expect("parse header"),
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).expect("decode claims"))
            .expect("parse claims"),
    )
}

pub(crate) fn decode_token_str(token: &str) -> (Value, Value) {
    let mut segments = token.split('.');
    let header = segments.next().expect("JWT header");
    let claims = segments.next().expect("JWT claims");
    assert!(segments.next().is_some());
    assert!(segments.next().is_none());
    (
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("decode header"))
            .expect("parse header"),
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).expect("decode claims"))
            .expect("parse claims"),
    )
}
