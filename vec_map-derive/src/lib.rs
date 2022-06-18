#[macro_export]
macro_rules! Token {
    (() $(pub)* struct $name:ident(pub usize);) => {
        impl vec_map::Token for $name {
            fn from_numeric_index(v: usize) -> Self {
                $name(v)
            }
        }
    };

    (() $(pub)* struct $name:ident(usize);) => {
        impl vec_map::Token for $name {
            fn from_numeric_index(v: usize) -> Self {
                $name(v)
            }
        }
    };
}

#[macro_export]
macro_rules! NumericIndex {
    (() $(pub)* struct $name:ident(pub usize);) => {
        impl vec_map::NumericIndex for $name {
            fn get_numeric_index(&self) -> usize {
                self.0
            }
        }
    };

    (() $(pub)* struct $name:ident(usize);) => {
        impl vec_map::NumericIndex for $name {
            fn get_numeric_index(&self) -> usize {
                self.0
            }
        }
    };
}

