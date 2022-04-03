use syn::ExprPath;

def_meta! {
    pub struct ContainerMeta {
        pub krate as "crate": Option<ExprPath>,
    }
}
