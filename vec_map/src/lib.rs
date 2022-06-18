/*!
 VecDict is a niche container inspired by LLVM's [IndexedMap], for mapping values that can be
 mapped to a small dense integer range, to some other type. It is internally implemented as a
 vector with a mapping function that maps the keys to the integers from the range.

 Token generation
 ----------------

 Sometimes all you need as a key is just a wrapper over `usize`. In that case you can use
 macros from the `vec_map-derive` crate (they require `custom_derive!` helper).

 ```rust
 use custom_derive::custom_derive;
 use vec_map_derive::{TokenTrait, NumericIndexTrait};

 custom_derive! {
     #[derive(TokenTrait, NumericIndexTrait)]
     struct SectionToken(usize);
 }
 ```

 [IndexedMap]: https://llvm.org/doxygen/IndexedMap_8h_source.html

 Right now, only [`VecDict`] is implemented, but the container will exist in several flavours.
 `VecMap` will store a copy of keys in a container (as well as the values, obviously). [`VecDict`]
 stores only the values. Array-backed `ArrMap` and `ArrDict` will have the upper bound of the
 range known at compile-time, thus enabling stack-allocation of the map.
*/

use std::marker::PhantomData;
use std::ops::Index;

pub trait NumericIndex {
    fn get_numeric_index(&self) -> usize;
}

pub trait Token {
    fn from_numeric_index(index: usize) -> Self;
}

use std::iter::{Enumerate, Filter};
use std::slice::Iter as SliceIter;
use std::slice::IterMut as SliceIterMut;

fn is_none_mut<V>(item: &(usize, &mut Option<V>)) -> bool {
    item.1.is_some()
}

fn is_none<V>(item: &(usize, &Option<V>)) -> bool {
    item.1.is_some()
}

type FilterPredicate<V> = fn(&(usize, &Option<V>)) -> bool;
type FilterPredicateMut<V> = fn(&(usize, &mut Option<V>)) -> bool;

type InternalIterType<'a, V> =
    Filter<Enumerate<SliceIter<'a, Option<V>>>, FilterPredicate<V>>;
type InternalIterMutType<'a, V> =
    Filter<Enumerate<SliceIterMut<'a, Option<V>>>, FilterPredicateMut<V>>;

pub struct TokIter<'a, K, V>
where
    K: 'a + Token + NumericIndex,
    V: 'a,
{
    iter: InternalIterType<'a, V>,
    phantom: PhantomData<K>,
}

pub struct TokIterMut<'a, K, V>
where
    K: 'a + Token + NumericIndex,
    V: 'a,
{
    iter: InternalIterMutType<'a, V>,
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

#[derive(Clone, Debug)]
pub struct VecDict<K, V>
where
    K: NumericIndex,
{
    vector: Vec<Option<V>>,
    phantom: PhantomData<K>,
}

impl<K, V> VecDict<K, V>
where
    K: NumericIndex,
{
    pub fn new(size: usize) -> Self {
        let mut vector = Vec::new();
        vector.resize_with(size, || None);
        VecDict {
            vector,
            phantom: PhantomData,
        }
    }

    pub fn clear(&mut self) {
        let size = self.vector.len();
        self.vector.clear();
        self.vector.resize_with(size, || None);
    }

    pub fn len(&self) -> usize {
        self.vector.len()
    }

    pub fn resize(&mut self, size: usize) {
        self.vector.resize_with(size, || None);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        match self.vector.get(key.get_numeric_index()) {
            Some(Some(v)) => Some(v),
            _ => None,
        }
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.vector[key.get_numeric_index()].is_some()
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        match self.vector.get_mut(key.get_numeric_index()) {
            Some(Some(v)) => Some(v),
            _ => None,
        }
    }

    pub fn insert(&mut self, key: &K, value: V) {
        self.vector[key.get_numeric_index()] = Some(value);
    }

    pub fn remove(&mut self, key: &K) {
        self.vector[key.get_numeric_index()] = None;
    }

    pub fn tok_iter(&self) -> TokIter<K, V>
    where
        K: Token,
    {
        TokIter {
            iter: self.vector.iter().enumerate().filter(is_none),
            phantom: PhantomData,
        }
    }

    pub fn tok_iter_mut(&mut self) -> TokIterMut<K, V>
    where
        K: Token,
    {
        TokIterMut {
            iter: self.vector.iter_mut().enumerate().filter(is_none_mut),
            phantom: PhantomData,
        }
    }
}

impl<K, V> Index<&K> for VecDict<K, V>
where
    K: NumericIndex,
{
    type Output = V;

    fn index(&self, key: &K) -> &Self::Output {
        self.vector[key.get_numeric_index()].as_ref().unwrap()
    }
}
