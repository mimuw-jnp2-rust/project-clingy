/*!
 VecDict is a niche container inspired by LLVM's [IndexedMap], for mapping values that can be
 mapped to a small dense integer range, to some other type. It is internally implemented as a
 vector with a mapping function that maps the keys to the integers from the range.

 Token generation
 ----------------

 Sometimes all you need as a key is just a wrapper over `usize`. In that case you can use
 macros from the `vec_map-derive` crate (they require `macro_rules!` helper).

 ```rust
 use custom_derive::custom_derive;
 use vec_map_derive::{TokenTrait, NumericIndexTrait};

 macro_attr! {
     #[derive(TokenTrait!, NumericIndexTrait!)]
     struct SectionToken(usize);
 }
 ```

 [IndexedMap]: https://llvm.org/doxygen/IndexedMap_8h_source.html

 Right now, only [`VecDict`] is implemented, but the container will exist in several flavours.
 `VecMap` will store a copy of keys in a container (as well as the values, obviously). [`VecDict`]
 stores only the values. Array-backed `ArrMap` and `ArrDict` will have the upper bound of the
 range known at compile-time, thus enabling stack-allocation of the map.
*/

pub mod tok_iter;

use std::marker::PhantomData;
use std::ops::{Index, IndexMut};

pub trait NumericIndex {
    fn get_numeric_index(&self) -> usize;
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

    pub fn capacity(&self) -> usize {
        self.vector.len()
    }

    pub fn len(&self) -> usize {
        self.vector.iter().filter(|slot| slot.is_some()).count()
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

impl<K, V> IndexMut<&K> for VecDict<K, V>
where
    K: NumericIndex,
{
    fn index_mut(&mut self, key: &K) -> &mut Self::Output {
        self.vector[key.get_numeric_index()].as_mut().unwrap()
    }
}
