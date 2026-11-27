//! [`named_enum!`](crate::named_enum): the registry of fs-inspect's enums, each value with a
//! stable name and a stable code.

/// An enum of named, numbered values: the enum and, from one list, its [`Named`] impl:
///
/// - `ALL` (every variant, in code order), `as_str` (the stable name, `snake_case`) and
///   `from_name`;
/// - `code` (the stable number, from 1; 0 is never a value, so it can mean "none" or "the
///   default") and `from_code`; `RETIRED`, the codes of removed values, which no value may take
///   again;
/// - `doc` (the value's documentation, its `///` lines as written);
///
/// and `Display` and serde by name. The names and codes are [`Named`]'s only: bring the trait
/// into scope to use them.
///
/// Every value of every enum a caller sees goes through here, so names and codes are defined
/// once; tests check that names and codes are unique and round-trip, and the generated tables
/// of the other interfaces are checked against them.
///
/// The enum is `#[non_exhaustive]` unless its name is followed by `exhaustive`; `default V;`
/// after the list makes `V` the `Default`. A variant takes documentation attributes only (`doc`
/// keeps them).
///
/// Exported for the other crates of the workspace: everything it refers to goes through
/// `$crate`, so a crate using it needs neither `serde` nor any import.
///
/// ```
/// use fs_inspect_io::names::Named;
/// fs_inspect_io::named_enum! {
///     /// A colour.
///     pub enum Colour ("colour") {
///         /// Red.
///         Red = 1 => "red",
///         DarkBlue = 3 => "dark_blue",
///     }
///     retired [2];
/// }
/// assert_eq!(Colour::DarkBlue.as_str(), "dark_blue");
/// assert_eq!(Colour::from_name("red"), Some(Colour::Red));
/// assert_eq!(Colour::from_code(3), Some(Colour::DarkBlue));
/// assert_eq!(Colour::Red.doc().trim(), "Red.");
/// assert_eq!(Colour::ALL.len(), 2);
/// assert_eq!(Colour::RETIRED, &[2]);
/// ```
#[macro_export]
macro_rules! named_enum {
    (
        $(#[$meta:meta])*
        pub enum $t:ident ($what:literal) exhaustive {
            $( $(#[doc = $vdoc:literal])* $v:ident = $code:literal => $name:literal, )*
        }
        $(retired [$($retired:literal),* $(,)?];)?
        $(default $def:ident;)?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $t {
            $( $(#[doc = $vdoc])* $v, )*
        }
        $crate::named_enum!(@impl $t $what [$($($retired),*)?] { $( [$($vdoc)*] $v = $code => $name, )* });
        $(impl ::core::default::Default for $t {
            fn default() -> Self {
                $t::$def
            }
        })?
    };
    (
        $(#[$meta:meta])*
        pub enum $t:ident ($what:literal) {
            $( $(#[doc = $vdoc:literal])* $v:ident = $code:literal => $name:literal, )*
        }
        $(retired [$($retired:literal),* $(,)?];)?
        $(default $def:ident;)?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $t {
            $( $(#[doc = $vdoc])* $v, )*
        }
        $crate::named_enum!(@impl $t $what [$($($retired),*)?] { $( [$($vdoc)*] $v = $code => $name, )* });
        $(impl ::core::default::Default for $t {
            fn default() -> Self {
                $t::$def
            }
        })?
    };
    (@impl $t:ident $what:literal [$($retired:literal),*] { $( [$($vdoc:literal)*] $v:ident = $code:literal => $name:literal, )* }) => {
        impl $crate::names::Named for $t {
            const WHAT: &'static str = $what;
            const RETIRED: &'static [u32] = &[$($retired),*];
            const ALL: &'static [$t] = &[$($t::$v),*];
            fn as_str(self) -> &'static str {
                match self {
                    $($t::$v => $name,)*
                }
            }
            fn code(self) -> u32 {
                match self {
                    $($t::$v => $code,)*
                }
            }
            fn doc(self) -> &'static str {
                match self {
                    $($t::$v => $crate::named_enum!(@doc $($vdoc)*),)*
                }
            }
        }

        impl ::core::fmt::Display for $t {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str($crate::names::Named::as_str(*self))
            }
        }

        impl $crate::__private::serde::Serialize for $t {
            fn serialize<S: $crate::__private::serde::Serializer>(
                &self,
                s: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                s.serialize_str($crate::names::Named::as_str(*self))
            }
        }

        impl<'de> $crate::__private::serde::Deserialize<'de> for $t {
            fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
                d: D,
            ) -> ::core::result::Result<Self, D::Error> {
                let name = <::std::borrow::Cow<'de, str> as $crate::__private::serde::Deserialize<'de>>::deserialize(d)?;
                <$t as $crate::names::Named>::from_name(&name).ok_or_else(|| {
                    <D::Error as $crate::__private::serde::de::Error>::custom(::std::format!(
                        ::core::concat!("unknown ", $what, " {:?}"),
                        name
                    ))
                })
            }
        }
    };
    (@doc) => { "" };
    (@doc $first:literal $($rest:literal)*) => {
        ::core::concat!($first $(, "\n", $rest)*)
    };
}

/// What every [`named_enum!`](crate::named_enum) enum is: its values' stable names and codes,
/// the one set of them (the enums have no inherent methods of the same).
pub trait Named: Copy + Eq + std::fmt::Debug + 'static {
    /// What the values are ("file system kind", ...), for messages.
    const WHAT: &'static str;
    /// The codes of removed values: no value takes one again.
    const RETIRED: &'static [u32];
    /// Every value, in code order.
    const ALL: &'static [Self];
    /// The stable name (`snake_case`).
    fn as_str(self) -> &'static str;
    /// The stable code (from 1; 0 is never a value).
    fn code(self) -> u32;
    /// The value's documentation, its `///` lines as written.
    fn doc(self) -> &'static str;
    /// The value named `name` ([`as_str`](Self::as_str)).
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == name)
    }
    /// The value of `code` ([`code`](Self::code)).
    fn from_code(code: u32) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.code() == code)
    }
}

/// An enum whose variants carry data, and its kind: a [`named_enum!`](crate::named_enum) of the
/// same variants (names, codes and documentation), with `kind()` telling which one a value is. The other
/// interfaces show such a value as its kind and the fields that kind has.
///
/// ```
/// fs_inspect_io::tagged_enum! {
///     /// Where a volume is mounted.
///     #[derive(Debug, Clone, PartialEq, Eq)]
///     pub enum Mount ("mount point") kind MountKind {
///         /// A drive letter.
///         Letter(char) = 1 => "letter",
///         /// A path.
///         Path { path: String } = 2 => "path",
///         /// Not mounted.
///         None = 3 => "none",
///     }
/// }
/// use fs_inspect_io::names::Named;
/// assert_eq!(Mount::Letter('C').kind(), MountKind::Letter);
/// assert_eq!(MountKind::Path.as_str(), "path");
/// ```
#[macro_export]
macro_rules! tagged_enum {
    (
        $(#[$meta:meta])*
        pub enum $t:ident ($what:literal) kind $k:ident exhaustive {
            $( $(#[doc = $vdoc:literal])* $v:ident $(( $($tup:tt)* ))? $({ $($fields:tt)* })? = $code:literal => $name:literal, )*
        }
    ) => {
        $(#[$meta])*
        pub enum $t {
            $( $(#[doc = $vdoc])* $v $(( $($tup)* ))? $({ $($fields)* })?, )*
        }
        $crate::named_enum! {
            #[doc = ::core::concat!("Which variant a [`", ::core::stringify!($t), "`] is.")]
            pub enum $k ($what) exhaustive {
                $( $(#[doc = $vdoc])* $v = $code => $name, )*
            }
        }
        $crate::tagged_enum!(@kind $t $k { $($v)* });
    };
    (
        $(#[$meta:meta])*
        pub enum $t:ident ($what:literal) kind $k:ident {
            $( $(#[doc = $vdoc:literal])* $v:ident $(( $($tup:tt)* ))? $({ $($fields:tt)* })? = $code:literal => $name:literal, )*
        }
    ) => {
        $(#[$meta])*
        #[non_exhaustive]
        pub enum $t {
            $( $(#[doc = $vdoc])* $v $(( $($tup)* ))? $({ $($fields)* })?, )*
        }
        $crate::named_enum! {
            #[doc = ::core::concat!("Which variant a [`", ::core::stringify!($t), "`] is.")]
            pub enum $k ($what) {
                $( $(#[doc = $vdoc])* $v = $code => $name, )*
            }
        }
        $crate::tagged_enum!(@kind $t $k { $($v)* });
    };
    (@kind $t:ident $k:ident { $($v:ident)* }) => {
        impl $t {
            /// Which variant it is.
            pub const fn kind(&self) -> $k {
                match self {
                    $($t::$v { .. } => $k::$v,)*
                }
            }
        }
    };
}
