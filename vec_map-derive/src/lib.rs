#[macro_export]
macro_rules! TokenTrait {
    (() $(pub)* struct $name:ident(pub usize);) => {
        impl Token for $name {
            fn from_numeric_index(v: usize) -> Self {
                $name(v)
            }
        }
    };

    (() $(pub)* struct $name:ident(usize);) => {
        impl Token for $name {
            fn from_numeric_index(v: usize) -> Self {
                $name(v)
            }
        }
    };
}

#[macro_export]
macro_rules! NumericIndexTrait {
    (() $(pub)* struct $name:ident(pub usize);) => {
        impl NumericIndex for $name {
            fn get_numeric_index(&self) -> usize {
                self.0
            }
        }
    };

    (() $(pub)* struct $name:ident(usize);) => {
        impl NumericIndex for $name {
            fn get_numeric_index(&self) -> usize {
                self.0
            }
        }
    };
}

