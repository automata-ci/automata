#![allow(dead_code)]

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use automata_ci_auth::{
    github::{
        DeviceCodeRequest, DeviceCodeResponse, DeviceTokenPollRequest, GithubAppConfig,
        GithubClientId, GithubCurrentUserRequest, GithubDevicePollResponse, GithubEndpoint,
        GithubEndpointError, GithubEndpointFuture, GithubEndpoints, GithubMembershipSnapshot,
        GithubTokenResponse, GithubUser, RefreshTokenRequest, WebTokenExchangeRequest,
    },
    human::{ProviderId, ProviderSubject},
    secret::{RandomnessError, SecretString, SecureRandom},
    time::{Clock, UnixTimestamp},
};
use url::Url;

#[derive(Debug)]
pub struct DeterministicRandom {
    next: Mutex<u8>,
}

impl DeterministicRandom {
    pub const fn new(first: u8) -> Self {
        Self {
            next: Mutex::new(first),
        }
    }
}

impl SecureRandom for DeterministicRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomnessError> {
        let mut next = self.next.lock().expect("deterministic random lock");
        destination.fill(*next);
        *next = next.wrapping_add(1);
        Ok(())
    }
}

#[derive(Debug)]
pub struct FixedClock(pub UnixTimestamp);

impl Clock for FixedClock {
    fn now(&self) -> UnixTimestamp {
        self.0
    }
}

#[derive(Debug, Default)]
pub struct ObservedRequests {
    pub web_calls: usize,
    pub web_code: Option<String>,
    pub web_verifier: Option<String>,
    pub device_code_calls: usize,
    pub device_poll_calls: usize,
    pub refresh_calls: usize,
    pub refresh_had_client_secret: Option<bool>,
    pub current_user_calls: usize,
    pub current_user_token: Option<String>,
    pub membership_calls: usize,
    pub membership_token: Option<String>,
}

#[derive(Debug, Default)]
pub struct MockGithubEndpoint {
    web: Mutex<VecDeque<Result<GithubTokenResponse, GithubEndpointError>>>,
    device_code: Mutex<VecDeque<Result<DeviceCodeResponse, GithubEndpointError>>>,
    device_poll: Mutex<VecDeque<Result<GithubDevicePollResponse, GithubEndpointError>>>,
    refresh: Mutex<VecDeque<Result<GithubTokenResponse, GithubEndpointError>>>,
    user: Mutex<VecDeque<Result<GithubUser, GithubEndpointError>>>,
    memberships: Mutex<VecDeque<Result<GithubMembershipSnapshot, GithubEndpointError>>>,
    pub observed: Mutex<ObservedRequests>,
}

impl MockGithubEndpoint {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn push_web(&self, response: Result<GithubTokenResponse, GithubEndpointError>) {
        self.web
            .lock()
            .expect("web response lock")
            .push_back(response);
    }

    pub fn push_device_code(&self, response: Result<DeviceCodeResponse, GithubEndpointError>) {
        self.device_code
            .lock()
            .expect("device code response lock")
            .push_back(response);
    }

    pub fn push_device_poll(
        &self,
        response: Result<GithubDevicePollResponse, GithubEndpointError>,
    ) {
        self.device_poll
            .lock()
            .expect("device poll response lock")
            .push_back(response);
    }

    pub fn push_refresh(&self, response: Result<GithubTokenResponse, GithubEndpointError>) {
        self.refresh
            .lock()
            .expect("refresh response lock")
            .push_back(response);
    }

    pub fn push_user(&self, response: Result<GithubUser, GithubEndpointError>) {
        self.user
            .lock()
            .expect("user response lock")
            .push_back(response);
    }

    pub fn push_memberships(
        &self,
        response: Result<GithubMembershipSnapshot, GithubEndpointError>,
    ) {
        self.memberships
            .lock()
            .expect("membership response lock")
            .push_back(response);
    }
}

fn next_or_unavailable<T>(
    queue: &Mutex<VecDeque<Result<T, GithubEndpointError>>>,
) -> Result<T, GithubEndpointError> {
    queue
        .lock()
        .expect("mock response lock")
        .pop_front()
        .unwrap_or(Err(GithubEndpointError::Unavailable))
}

impl GithubEndpoint for MockGithubEndpoint {
    fn exchange_web_code<'a>(
        &'a self,
        request: WebTokenExchangeRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubTokenResponse> {
        let mut observed = self.observed.lock().expect("observed request lock");
        observed.web_calls += 1;
        observed.web_code = Some(request.code.expose_secret().to_owned());
        observed.web_verifier = Some(request.code_verifier.expose_secret().to_owned());
        drop(observed);
        let response = next_or_unavailable(&self.web);
        Box::pin(async move { response })
    }

    fn request_device_code<'a>(
        &'a self,
        _request: DeviceCodeRequest<'a>,
    ) -> GithubEndpointFuture<'a, DeviceCodeResponse> {
        self.observed
            .lock()
            .expect("observed request lock")
            .device_code_calls += 1;
        let response = next_or_unavailable(&self.device_code);
        Box::pin(async move { response })
    }

    fn poll_device_token<'a>(
        &'a self,
        _request: DeviceTokenPollRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubDevicePollResponse> {
        self.observed
            .lock()
            .expect("observed request lock")
            .device_poll_calls += 1;
        let response = next_or_unavailable(&self.device_poll);
        Box::pin(async move { response })
    }

    fn refresh_token<'a>(
        &'a self,
        request: RefreshTokenRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubTokenResponse> {
        let mut observed = self.observed.lock().expect("observed request lock");
        observed.refresh_calls += 1;
        observed.refresh_had_client_secret = Some(request.client_secret.is_some());
        drop(observed);
        let response = next_or_unavailable(&self.refresh);
        Box::pin(async move { response })
    }

    fn current_user<'a>(
        &'a self,
        request: GithubCurrentUserRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubUser> {
        let mut observed = self.observed.lock().expect("observed request lock");
        observed.current_user_calls += 1;
        observed.current_user_token = Some(request.access_token.expose_secret().to_owned());
        drop(observed);
        let response = next_or_unavailable(&self.user);
        Box::pin(async move { response })
    }

    fn memberships<'a>(
        &'a self,
        request: GithubCurrentUserRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubMembershipSnapshot> {
        let mut observed = self.observed.lock().expect("observed request lock");
        observed.membership_calls += 1;
        observed.membership_token = Some(request.access_token.expose_secret().to_owned());
        drop(observed);
        let response = next_or_unavailable(&self.memberships);
        Box::pin(async move { response })
    }
}

pub(crate) fn provider_id() -> ProviderId {
    ProviderId::new("github").expect("provider ID")
}

pub(crate) fn provider_subject() -> ProviderSubject {
    ProviderSubject::new("42").expect("provider subject")
}

pub fn config() -> GithubAppConfig {
    GithubAppConfig::new(
        ProviderId::new("github").expect("provider ID"),
        GithubClientId::new("Iv1abc123").expect("client ID"),
        secret("client-secret-never-log"),
        Url::parse("https://automata.example/auth/github/callback").expect("callback URL"),
        GithubEndpoints::github_dot_com().expect("GitHub endpoints"),
        600,
    )
    .expect("GitHub config")
}

pub fn secret(value: &str) -> SecretString {
    SecretString::new(value).expect("non-empty test secret")
}

pub fn token_response() -> GithubTokenResponse {
    GithubTokenResponse {
        access_token: secret("ghu_access_token_value"),
        expires_in: Some(28_800),
        refresh_token: Some(secret("ghr_refresh_token_value")),
        refresh_token_expires_in: Some(15_897_600),
        scope: String::new(),
        token_type: "bearer".to_owned(),
    }
}
