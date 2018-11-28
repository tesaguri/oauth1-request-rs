use std::borrow::Borrow;
use std::collections::BTreeSet;

use super::{OAuth1Authorize, Options, Request, SignatureMethod, Signer};

impl<'a, A: OAuth1Authorize> OAuth1Authorize for &'a A {
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        (**self).authorize_with(signer, consumer_key, options)
    }
}

impl<'a, A: OAuth1Authorize> OAuth1Authorize for &'a mut A {
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        (**self).authorize_with(signer, consumer_key, options)
    }
}

/// Authorizes a request with no query pairs.
impl OAuth1Authorize for () {
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        signer.finish(consumer_key, options)
    }
}

impl<K: Borrow<str>, V: Borrow<str>> OAuth1Authorize for BTreeSet<(K, V)> {
    fn authorize_with<SM>(
        &self,
        mut signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        let mut params = self.iter().map(|&(ref k, ref v)| (k.borrow(), v.borrow()));

        let (mut signer, mut pair) = loop {
            let (k, v) = match params.next() {
                Some(kv) => kv,
                None => break (signer.oauth_parameters(consumer_key, options), None),
            };
            if k > "oauth_" {
                break (signer.oauth_parameters(consumer_key, options), Some((k, v)));
            }
            signer.parameter(k, v);
        };

        while let Some((k, v)) = pair {
            signer.parameter(k, v);
            pair = params.next();
        }

        signer.finish()
    }
}

impl<A: OAuth1Authorize> OAuth1Authorize for Option<A> {
    fn authorize_with<SM>(
        &self,
        signer: Signer<SM>,
        consumer_key: &str,
        options: Option<&Options>,
    ) -> Request
    where
        SM: SignatureMethod,
    {
        if let Some(ref this) = *self {
            this.authorize_with(signer, consumer_key, options)
        } else {
            signer.finish(consumer_key, options)
        }
    }
}
