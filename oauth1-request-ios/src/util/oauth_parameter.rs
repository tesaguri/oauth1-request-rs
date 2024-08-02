use core::cmp::{Ordering, PartialEq, PartialOrd};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OAuthParameter {
    Callback,
    ConsumerKey,
    Nonce,
    SignatureMethod,
    Timestamp,
    Token,
    Verifier,
    Version,
    None,
}

impl OAuthParameter {
    pub fn next(self) -> OAuthParameter {
        match self {
            OAuthParameter::Callback => OAuthParameter::ConsumerKey,
            OAuthParameter::ConsumerKey => OAuthParameter::Nonce,
            OAuthParameter::Nonce => OAuthParameter::SignatureMethod,
            OAuthParameter::SignatureMethod => OAuthParameter::Timestamp,
            OAuthParameter::Timestamp => OAuthParameter::Token,
            OAuthParameter::Token => OAuthParameter::Verifier,
            OAuthParameter::Verifier => OAuthParameter::Version,
            OAuthParameter::Version => OAuthParameter::None,
            OAuthParameter::None => {
                debug_assert!(false, "called `next` on an `OAuthParameter::None`");
                OAuthParameter::Callback
            }
        }
    }

    fn as_str(self) -> Option<&'static str> {
        match self {
            OAuthParameter::Callback => Some("oauth_callback"),
            OAuthParameter::ConsumerKey => Some("oauth_consumer_key"),
            OAuthParameter::Nonce => Some("oauth_nonce"),
            OAuthParameter::SignatureMethod => Some("oauth_signature_method"),
            OAuthParameter::Timestamp => Some("oauth_timestamp"),
            OAuthParameter::Token => Some("oauth_token"),
            OAuthParameter::Verifier => Some("oauth_verifier"),
            OAuthParameter::Version => Some("oauth_version"),
            OAuthParameter::None => None,
        }
    }
}

impl Default for OAuthParameter {
    fn default() -> Self {
        OAuthParameter::Callback
    }
}

impl PartialEq<str> for OAuthParameter {
    fn eq(&self, s: &str) -> bool {
        match self.as_str() {
            Some(t) => t == s,
            None => false,
        }
    }
}

impl PartialOrd<str> for OAuthParameter {
    fn partial_cmp(&self, s: &str) -> Option<Ordering> {
        match self.as_str() {
            Some(t) => t.partial_cmp(s),
            None => Some(Ordering::Greater),
        }
    }
}
