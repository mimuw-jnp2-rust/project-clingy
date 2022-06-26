/*!
 `VecDict` struct does not store the keys as a part of the map (it stores only the values),
 however, if the key is a simple wrapper over `usize` (Token), it can be reconstructed from
 index and iterated over.
*/

use crate::{NumericIndex, VecDict};
use core::marker::PhantomData;
use std::iter::{Enumerate, Filter};
use std::slice::Iter as SliceIter;
use std::slice::IterMut as SliceIterMut;

type FilterPredicate<V> = fn(&(usize, &Option<V>)) -> bool;
type FilterPredicateMut<V> = fn(&(usize, &mut Option<V>)) -> bool;

pub trait Token {
    fn from_numeric_index(index: usize) -> Self;
}

fn tok_is_none_mut<V>(item: &(usize, &mut Option<V>)) -> bool {
    item.1.is_some()
}

fn tok_is_none<V>(item: &(usize, &Option<V>)) -> bool {
    item.1.is_some()
}

type InternalTokIterType<'a, V> =
    Filter<Enumerate<SliceIter<'a, Option<V>>>, FilterPredicate<V>>;
type InternalTokIterMutType<'a, V> =
    Filter<Enumerate<SliceIterMut<'a, Option<V>>>, FilterPredicateMut<V>>;

#[derive(Clone)]
pub struct TokIter<'a, K, V>
where
    K: 'a + Token + NumericIndex,
    V: 'a,
{
    iter: InternalTokIterType<'a, V>,
    phantom: PhantomData<K>,
}

pub struct TokIterMut<'a, K, V>
where
    K: 'a + Token + NumericIndex,
    V: 'a,
{
    iter: InternalTokIterMutType<'a, V>,
    phantom: PhantomData<K>,
}

impl<'a, K, V> Iterator for TokIter<'a, K, V>
where
    K: 'a + Token + NumericIndex,
    V: 'a,
{
    type Item = (K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some((index, value)) => {
                let key = K::from_numeric_index(index);
                Some((key, value.as_ref().unwrap()))
            }
            None => None,
        }
    }
}

impl<'a, K, V> Iterator for TokIterMut<'a, K, V>
where
    K: 'a + Token + NumericIndex,
    V: 'a,
{
    type Item = (K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some((index, value)) => {
                let key = K::from_numeric_index(index);
                Some((key, value.as_mut().unwrap()))
            }
            None => None,
        }
    }
}

impl<K, V> VecDict<K, V>
where
    K: NumericIndex,
{
    pub fn tok_iter(&self) -> TokIter<K, V>
    where
        K: Token,
    {
        TokIter {
            iter: self.vector.iter().enumerate().filter(tok_is_none),
            phantom: PhantomData,
        }
    }

    pub fn tok_iter_mut(&mut self) -> TokIterMut<K, V>
    where
        K: Token,
    {
        TokIterMut {
            iter: self.vector.iter_mut().enumerate().filter(tok_is_none_mut),
            phantom: PhantomData,
        }
    }
}
