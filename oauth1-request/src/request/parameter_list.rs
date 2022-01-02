//! A [`Request`] with dynamic list of key-value parameter pairs.

use core::borrow::Borrow;
use core::cmp::Ordering;
use core::fmt::Display;
use core::iter::{Extend, FromIterator};
use core::marker::PhantomData;

use super::Request;
use crate::serializer::Serializer;
use crate::util::OAuthParameter;

/// A [`Request`] with dynamic list of key-value parameter pairs.
///
/// This is like an array of `(K, V)` but the parameters are guaranteed to be sorted alphabetically.
///
/// ## Example
///
/// ```
/// # extern crate oauth1_request as oauth;
/// #
/// use oauth::request::ParameterList;
///
/// let request = ParameterList::new([
///     ("foo", 123),
///     ("bar", 23),
///     ("foo", 3),
/// ]);
///
/// let form = oauth::to_form_urlencoded(&request);
/// assert_eq!(form, "bar=23&foo=123&foo=3");
/// ```
pub struct ParameterList<
    K,
    V,
    #[cfg(feature = "alloc")] A = Vec<(K, V)>,
    #[cfg(not(feature = "alloc"))] A,
    P = (K, V),
> {
    list: A,
    #[allow(clippy::type_complexity)]
    marker: PhantomData<fn() -> (K, V, P)>,
}

/// An iterator over the elements of [`ParameterList`].
///
/// This struct is created by [`ParameterList::iter`] method.
pub struct Iter<'a, K, V, P> {
    inner: core::slice::Iter<'a, P>,
    marker: PhantomData<fn() -> (K, V)>,
}

impl<K, V, A, P> ParameterList<K, V, A, P>
where
    K: AsRef<str>,
    V: Display,
    A: AsRef<[P]>,
    P: Borrow<(K, V)>,
{
    /// Creates a new `ParameterList` from sorted `list`.
    ///
    /// Returns `None` if `list` is not sorted.
    pub fn from_sorted(list: A) -> Option<Self> {
        is_sorted_by(list.as_ref(), cmp).then(|| ParameterList {
            list,
            marker: PhantomData,
        })
    }
}

impl<K, V, A, P> ParameterList<K, V, A, P>
where
    K: AsRef<str>,
    V: Display,
    A: AsRef<[P]> + AsMut<[P]>,
    P: Borrow<(K, V)>,
{
    /// Creates a new `ParameterList` from `list`.
    ///
    /// This function sorts `list`.
    pub fn new(list: A) -> Self {
        let mut ret = ParameterList {
            list,
            marker: PhantomData,
        };
        ret.sort();
        ret
    }
}

impl<K, V, A, P> ParameterList<K, V, A, P>
where
    K: AsRef<str>,
    V: Display,
    A: AsMut<[P]>,
    P: Borrow<(K, V)>,
{
    fn sort(&mut self) {
        self.list.as_mut().sort_unstable_by(cmp);
    }
}

impl<K, V, A, P> ParameterList<K, V, A, P>
where
    A: AsRef<[P]>,
    P: Borrow<(K, V)>,
{
    /// Returns an iterator over entries of the `ParameterList`.
    pub fn iter(&self) -> Iter<'_, K, V, P> {
        Iter {
            inner: self.list.as_ref().iter(),
            marker: PhantomData,
        }
    }
}

impl<K, V, A, P> AsRef<[P]> for ParameterList<K, V, A, P>
where
    A: AsRef<[P]>,
{
    fn as_ref(&self) -> &[P] {
        self.list.as_ref()
    }
}

impl<K, V, A, P> Default for ParameterList<K, V, A, P>
where
    K: AsRef<str>,
    V: Display,
    A: AsRef<[P]> + Default,
    P: Borrow<(K, V)>,
{
    fn default() -> Self {
        ParameterList {
            list: A::default(),
            marker: PhantomData,
        }
    }
}

impl<K, V, A, P> From<A> for ParameterList<K, V, A, P>
where
    K: AsRef<str>,
    V: Display,
    A: AsRef<[P]> + AsMut<[P]>,
    P: Borrow<(K, V)>,
{
    fn from(list: A) -> Self {
        ParameterList::new(list)
    }
}

impl<K, V, A, P> FromIterator<P> for ParameterList<K, V, A, P>
where
    K: AsRef<str>,
    V: Display,
    A: AsRef<[P]> + AsMut<[P]> + FromIterator<P>,
    P: Borrow<(K, V)>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = P>,
    {
        ParameterList::new(iter.into_iter().collect())
    }
}

impl<K, V, A, P> Extend<P> for ParameterList<K, V, A, P>
where
    K: AsRef<str>,
    V: Display,
    A: AsMut<[P]> + Extend<P>,
    P: Borrow<(K, V)>,
{
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = P>,
    {
        self.list.extend(iter);
        self.sort();
    }
}

impl<K, V, A, P> Request for ParameterList<K, V, A, P>
where
    K: AsRef<str>,
    V: Display,
    A: AsRef<[P]>,
    P: Borrow<(K, V)>,
{
    fn serialize<S>(&self, serializer: S) -> S::Output
    where
        S: Serializer,
    {
        return inner::<S, K, V, P>(self.list.as_ref(), serializer);

        fn inner<S, K, V, P>(this: &[P], mut serializer: S) -> S::Output
        where
            S: Serializer,
            K: AsRef<str>,
            V: Display,
            P: Borrow<(K, V)>,
        {
            let mut next_param = OAuthParameter::default();

            for pair in this {
                let (k, v) = pair.borrow();
                let k = k.as_ref();
                while next_param < *k {
                    next_param.serialize(&mut serializer);
                    next_param = next_param.next();
                }
                serializer.serialize_parameter(k, v);
            }

            while next_param != OAuthParameter::None {
                next_param.serialize(&mut serializer);
                next_param = next_param.next();
            }

            serializer.end()
        }
    }
}

impl<'a, K: 'a, V: 'a, P> Iterator for Iter<'a, K, V, P>
where
    P: Borrow<(K, V)>,
{
    type Item = &'a (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Borrow::borrow)
    }
}

fn cmp<K, V, P>(lhs: &P, rhs: &P) -> Ordering
where
    K: AsRef<str>,
    V: Display,
    P: Borrow<(K, V)>,
{
    let (ref kl, ref vl) = *lhs.borrow();
    let (ref kr, ref vr) = *rhs.borrow();
    (kl.as_ref(), fmt_cmp::Cmp(vl)).cmp(&(kr.as_ref(), fmt_cmp::Cmp(vr)))
}

// TODO: Use `<[T]>::is_sorted_by` once it's stable.
// <https://github.com/rust-lang/rust/pull/55045>
fn is_sorted_by<T, F>(slice: &[T], mut cmp: F) -> bool
where
    F: FnMut(&T, &T) -> Ordering,
{
    slice
        .windows(2)
        .all(|slice| cmp(&slice[1], &slice[0]).is_ge())
}
