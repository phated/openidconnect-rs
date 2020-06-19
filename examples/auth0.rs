//!
//! This example showcases the process of integrating with the
//! [Auth0 OpenID Connect](https://developers.google.com/identity/protocols/OpenIDConnect)
//! provider.
//!
//! Before running it, you'll need to generate your own Auth0 OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! AUTH0_CLIENT_ID=xxx AUTH0_CLIENT_SECRET=yyy cargo run --example auth0
//! ```
//!
//! ...and follow the instructions.
//!

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::exit;

use failure::Fail;
use url::Url;

use http_client::h1::H1Client;
use http_client::HttpClient;
use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::http_types::{Request, Response};
use openidconnect::{
    AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret,
    CodeTokenRequest, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
};
use openidconnect::{OAuth2TokenResponse, TokenResponse};

fn handle_error<T: Fail>(fail: &T, msg: &'static str) {
    let mut err_msg = format!("ERROR: {}", msg);
    let mut cur_fail: Option<&dyn Fail> = Some(fail);
    while let Some(cause) = cur_fail {
        err_msg += &format!("\n    caused by: {}", cause);
        cur_fail = cause.cause();
    }
    println!("{}", err_msg);
    exit(1);
}

#[derive(Debug, Fail)]
pub enum Error {
    /// Error returned by reqwest crate.
    //  #[fail(display = "request failed")]
    //  Reqwest(#[cause] T),
    /// Non-reqwest HTTP error.
    //  #[fail(display = "HTTP error")]
    //  Http(#[cause] http_types::Error),
    /// I/O error.
    #[fail(display = "I/O error")]
    Io(#[cause] std::io::Error),
    /// Other error.
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}

pub async fn async_http_client(request: Request) -> Result<Response, Error> {
    let client = H1Client::new();
    match client.send(request).await {
        Ok(response) => Ok(response),
        Err(_) => Err(Error::Other("Something broke".into())),
    }
}

fn main() {
    smol::run(async {
        env_logger::init();

        let auth0_client_id = ClientId::new(
            env::var("AUTH0_CLIENT_ID").expect("Missing the AUTH0_CLIENT_ID environment variable."),
        );
        let auth0_client_secret = ClientSecret::new(
            env::var("AUTH0_CLIENT_SECRET")
                .expect("Missing the AUTH0_CLIENT_SECRET environment variable."),
        );
        let issuer_url = IssuerUrl::new("https://twentyfive-stars.us.auth0.com/".to_string())
            .expect("Invalid issuer URL");

        // Fetch Auth0's OpenID Connect discovery document.
        let provider_metadata = CoreProviderMetadata::discover(issuer_url, async_http_client)
            .await
            .unwrap_or_else(|err| {
                handle_error(&err, "Failed to discover OpenID Provider");
                unreachable!();
            });
        println!("{:?}", provider_metadata);

        // Set up the config for the Auth0 OAuth2 process.
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            auth0_client_id,
            Some(auth0_client_secret),
        )
        // This example will be running its own server at localhost:8080.
        // See below for the server implementation.
        .set_redirect_uri(
            RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect URL"),
        );

        // Generate the authorization URL to which we'll redirect the user.
        let (authorize_url, csrf_state, nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // This example is requesting access to the "calendar" features and the user's profile.
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        println!(
            "Open this URL in your browser:\n{}\n",
            authorize_url.to_string()
        );

        // A very naive implementation of the redirect server.
        let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let code;
                let state;
                {
                    let mut reader = BufReader::new(&stream);

                    let mut request_line = String::new();
                    reader.read_line(&mut request_line).unwrap();

                    let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                    let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                    let code_pair = url
                        .query_pairs()
                        .find(|pair| {
                            let &(ref key, _) = pair;
                            key == "code"
                        })
                        .unwrap();

                    let (_, value) = code_pair;
                    code = AuthorizationCode::new(value.into_owned());

                    let state_pair = url
                        .query_pairs()
                        .find(|pair| {
                            let &(ref key, _) = pair;
                            key == "state"
                        })
                        .unwrap();

                    let (_, value) = state_pair;
                    state = CsrfToken::new(value.into_owned());
                }

                let message = "Go back to your terminal :)";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    message.len(),
                    message
                );
                stream.write_all(response.as_bytes()).unwrap();

                println!("Auth0 returned the following code:\n{}\n", code.secret());
                println!(
                    "Auth0 returned the following state:\n{} (expected `{}`)\n",
                    state.secret(),
                    csrf_state.secret()
                );

                // Exchange the code with a token.
                let token_response = client
                    .exchange_code(code)
                    .request(async_http_client)
                    .await
                    .unwrap();

                println!("{:?}", token_response);

                println!(
                    "Auth0 returned access token:\n{:?}\n",
                    token_response.id_token()
                );
                println!("Auth0 returned scopes: {:?}", token_response.scopes());

                let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
                let id_token_claims: &CoreIdTokenClaims = token_response
                    .extra_fields()
                    .id_token()
                    .expect("Server did not return an ID token")
                    .claims(&id_token_verifier, &nonce)
                    .unwrap_or_else(|err| {
                        handle_error(&err, "Failed to verify ID token");
                        unreachable!();
                    });
                println!("Auth0 returned ID token: {:?}", id_token_claims);

                // The server will terminate itself after collecting the first code.
                break;
            }
        }
    });
}
