#![no_std]

extern crate alloc;

extern crate oauth1_request as oauth;

use oauth::serializer::{Serializer, SerializerExt};

#[macro_use]
mod common;

assert_expand! {
    #[derive(oauth::Request)]
    struct NoStd[][] {
        plain: u64 = 42,

        alloc_ty: alloc::string::String = alloc::string::String::new(),

        #[oauth1(option = true)]
        option: core::option::Option<u64> = core::option::Option::Some(42_u64),

        #[oauth1(fmt = crate::common::fmt_ignore)]
        fmt: (),

        #[oauth1(skip_if = crate::common::always)]
        skip_if: u64 = 42,
    }
    |this, mut ser| {
        ser.serialize_parameter("alloc_ty", &*this.alloc_ty);
        ser.serialize_parameter("fmt", "");
        ser.serialize_oauth_parameters();
        if let Some(option) = this.option {
            ser.serialize_parameter("option", option);
        }
        ser.serialize_parameter("plain", this.plain);
        ser.end()
    }
}
