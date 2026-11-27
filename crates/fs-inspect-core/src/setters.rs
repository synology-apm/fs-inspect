//! `with_*` setters for the option structs of the stable layer: they are `#[non_exhaustive]`
//! (a field can be added without a major release), so a caller outside their crate builds one
//! from `T::default()` and these.

/// `impl T { pub fn with_f(self, v: Ty) -> Self }` for each `f / with_f: Ty`.
#[doc(hidden)]
#[macro_export]
macro_rules! with_setters {
    ($ty:ty { $($f:ident / $with:ident : $t:ty),* $(,)? }) => {
        impl $ty {
            $(
                #[doc = concat!("Sets [`", stringify!($f), "`](Self::", stringify!($f), ").")]
                #[must_use]
                pub fn $with(mut self, v: $t) -> Self {
                    self.$f = v;
                    self
                }
            )*
        }
    };
}
