use anyhow::{anyhow, Context as _};
use cargo_metadata as cm;
use itertools::chain;
use maplit::btreemap;
use ra_ap_paths::AbsPath;
use ra_ap_proc_macro_api::{
    msg::PanicMessage, MacroDylib, ProcMacro, ProcMacroKind, ProcMacroServer,
};
use ra_ap_tt::{self as tt, DelimiterKind, Leaf, TokenId};
use semver::Version;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MSRV: Version = Version::new(1, 64, 0);

pub(crate) fn list_proc_macro_dylibs<P: FnMut(&cm::PackageId) -> bool>(
    cargo_messages: &[cm::Message],
    mut filter: P,
) -> BTreeMap<&cm::PackageId, &AbsPath> {
    cargo_messages
        .iter()
        .flat_map(|message| match message {
            cm::Message::CompilerArtifact(artifact) => Some(artifact),
            _ => None,
        })
        .filter(|cm::Artifact { target, .. }| target.is_proc_macro())
        .filter(|cm::Artifact { package_id, .. }| filter(package_id))
        .flat_map(
            |cm::Artifact {
                 package_id,
                 filenames,
                 ..
             }| {
                filenames
                    .first()
                    .map(|filename| (package_id, AbsPath::assert(filename.as_ref())))
            },
        )
        .collect()
}

pub struct ProcMacroExpander<'msg> {
    custom_derive: BTreeMap<String, (&'msg cm::PackageId, ProcMacro)>,
    func_like: BTreeMap<String, (&'msg cm::PackageId, ProcMacro)>,
    attr: BTreeMap<String, (&'msg cm::PackageId, ProcMacro)>,
}

impl<'msg> ProcMacroExpander<'msg> {
    pub(crate) fn spawn(
        proc_macro_srv_exe: &AbsPath,
        dylib_paths: &BTreeMap<&'msg cm::PackageId, &'msg AbsPath>,
    ) -> anyhow::Result<Self> {
        let server = ProcMacroServer::spawn(proc_macro_srv_exe.to_path_buf())?;

        let mut custom_derive = btreemap!();
        let mut func_like = btreemap!();
        let mut attr = btreemap!();

        for (&package_id, dylib_path) in dylib_paths {
            let proc_macros = server
                .load_dylib(MacroDylib::new(dylib_path.to_path_buf()))
                .map_err(|e| anyhow!("{}", e))
                .with_context(|| "rust-analyzer error")?;

            for proc_macro in proc_macros {
                match proc_macro.kind() {
                    ProcMacroKind::CustomDerive => &mut custom_derive,
                    ProcMacroKind::FuncLike => &mut func_like,
                    ProcMacroKind::Attr => &mut attr,
                }
                .insert(proc_macro.name().to_owned(), (package_id, proc_macro));
            }
        }

        Ok(Self {
            custom_derive,
            func_like,
            attr,
        })
    }

    pub(crate) fn macro_names(
        &self,
    ) -> impl Iterator<Item = (&'msg cm::PackageId, BTreeSet<&str>)> {
        let mut names = BTreeMap::<_, BTreeSet<_>>::new();
        for (name, &(pkg, _)) in chain!(&self.custom_derive, &self.func_like, &self.attr) {
            names.entry(pkg).or_default().insert(&**name);
        }
        names.into_iter()
    }

    pub(crate) fn attempt_expand_custom_derive(
        &mut self,
        name: &str,
        body: impl FnOnce() -> proc_macro2::TokenStream,
    ) -> anyhow::Result<Option<proc_macro2::Group>> {
        self.attempt_expand(name, ProcMacroKind::CustomDerive, body, None::<fn() -> _>)
    }

    pub(crate) fn attempt_expand_func_like(
        &mut self,
        name: &str,
        body: impl FnOnce() -> proc_macro2::TokenStream,
    ) -> anyhow::Result<Option<proc_macro2::Group>> {
        self.attempt_expand(name, ProcMacroKind::FuncLike, body, None::<fn() -> _>)
    }

    pub(crate) fn attempt_expand_attr(
        &mut self,
        name: &str,
        body: impl FnOnce() -> proc_macro2::TokenStream,
        attr: impl FnOnce() -> proc_macro2::Group,
    ) -> anyhow::Result<Option<proc_macro2::Group>> {
        self.attempt_expand(name, ProcMacroKind::Attr, body, Some(attr))
    }

    fn attempt_expand(
        &self,
        name: &str,
        kind: ProcMacroKind,
        subtree: impl FnOnce() -> proc_macro2::TokenStream,
        attr: Option<impl FnOnce() -> proc_macro2::Group>,
    ) -> anyhow::Result<Option<proc_macro2::Group>> {
        match kind {
            ProcMacroKind::CustomDerive => &self.custom_derive,
            ProcMacroKind::FuncLike => &self.func_like,
            ProcMacroKind::Attr => &self.attr,
        }
        .get(name)
        .map(|(_, proc_macro)| {
            let output = &proc_macro
                .expand(
                    &from_proc_macro2_group(&proc_macro2::Group::new(
                        proc_macro2::Delimiter::None,
                        subtree(),
                    )),
                    attr.map(|f| from_proc_macro2_group(&f())).as_ref(),
                    vec![],
                )
                .map_err(|e| anyhow!("{}", e))
                .with_context(|| "rust-analyzer error")?
                .map_err(|PanicMessage(s)| anyhow!("proc macro paniced: {s:?}"))?;
            Ok(from_ra_subtree(output))
        })
        .transpose()
    }
}

fn from_proc_macro2_group(group: &proc_macro2::Group) -> tt::Subtree<TokenId> {
    return tt::Subtree {
        delimiter: from_proc_macro2_delimiter(group.delimiter()),
        token_trees: group
            .stream()
            .into_iter()
            .map(|tt| from_proc_macro2_token_tree(&tt))
            .collect(),
    };

    fn from_proc_macro2_delimiter(delimiter: proc_macro2::Delimiter) -> tt::Delimiter<TokenId> {
        tt::Delimiter {
            open: TokenId::unspecified(),
            close: TokenId::unspecified(),
            kind: match delimiter {
                proc_macro2::Delimiter::Parenthesis => DelimiterKind::Parenthesis,
                proc_macro2::Delimiter::Brace => DelimiterKind::Brace,
                proc_macro2::Delimiter::Bracket => DelimiterKind::Bracket,
                proc_macro2::Delimiter::None => DelimiterKind::Invisible,
            },
        }
    }

    fn from_proc_macro2_token_tree(tt: &proc_macro2::TokenTree) -> tt::TokenTree<TokenId> {
        match tt {
            proc_macro2::TokenTree::Group(g) => from_proc_macro2_group(g).into(),
            proc_macro2::TokenTree::Ident(i) => Leaf::from(from_proc_macro2_ident(i)).into(),
            proc_macro2::TokenTree::Punct(p) => Leaf::from(from_proc_macro2_punct(p)).into(),
            proc_macro2::TokenTree::Literal(l) => Leaf::from(from_proc_macro2_literal(l)).into(),
        }
    }

    fn from_proc_macro2_ident(ident: &proc_macro2::Ident) -> tt::Ident<TokenId> {
        tt::Ident {
            text: ident.to_string().into(),
            span: TokenId::unspecified(),
        }
    }

    fn from_proc_macro2_punct(punct: &proc_macro2::Punct) -> tt::Punct<TokenId> {
        tt::Punct {
            char: punct.as_char(),
            spacing: from_proc_macro2_spacing(punct.spacing()),
            span: TokenId::unspecified(),
        }
    }

    fn from_proc_macro2_spacing(spacing: proc_macro2::Spacing) -> tt::Spacing {
        match spacing {
            proc_macro2::Spacing::Alone => tt::Spacing::Alone,
            proc_macro2::Spacing::Joint => tt::Spacing::Joint,
        }
    }

    fn from_proc_macro2_literal(lit: &proc_macro2::Literal) -> tt::Literal<TokenId> {
        tt::Literal {
            text: lit.to_string().into(),
            span: TokenId::unspecified(),
        }
    }
}

fn from_ra_subtree(subtree: &tt::Subtree<impl Copy>) -> proc_macro2::Group {
    return proc_macro2::Group::new(
        from_ra_delimiter(subtree.delimiter),
        subtree.token_trees.iter().map(from_ra_token_tree).collect(),
    );

    fn from_ra_delimiter(delimiter: tt::Delimiter<impl Copy>) -> proc_macro2::Delimiter {
        match delimiter.kind {
            DelimiterKind::Parenthesis => proc_macro2::Delimiter::Parenthesis,
            DelimiterKind::Brace => proc_macro2::Delimiter::Brace,
            DelimiterKind::Bracket => proc_macro2::Delimiter::Bracket,
            DelimiterKind::Invisible => proc_macro2::Delimiter::None,
        }
    }

    fn from_ra_token_tree(tt: &tt::TokenTree<impl Copy>) -> proc_macro2::TokenTree {
        match tt {
            tt::TokenTree::Subtree(s) => proc_macro2::TokenTree::Group(from_ra_subtree(s)),
            tt::TokenTree::Leaf(Leaf::Ident(i)) => from_ra_ident(i).into(),
            &tt::TokenTree::Leaf(Leaf::Punct(p)) => from_ra_punct(p).into(),
            tt::TokenTree::Leaf(Leaf::Literal(l)) => from_ra_literal(l).into(),
        }
    }

    fn from_ra_ident(ident: &tt::Ident<impl Copy>) -> proc_macro2::Ident {
        proc_macro2::Ident::new(&ident.text, proc_macro2::Span::call_site())
    }

    fn from_ra_punct(punct: tt::Punct<impl Copy>) -> proc_macro2::Punct {
        proc_macro2::Punct::new(punct.char, from_ra_spacing(punct.spacing))
    }

    fn from_ra_spacing(spacing: tt::Spacing) -> proc_macro2::Spacing {
        match spacing {
            tt::Spacing::Alone => proc_macro2::Spacing::Alone,
            tt::Spacing::Joint => proc_macro2::Spacing::Joint,
        }
    }

    fn from_ra_literal(lit: &tt::Literal<impl Copy>) -> proc_macro2::Literal {
        syn::parse_str(&lit.text)
            .unwrap_or_else(|e| panic!("could not parse {:?} as a literal: {}", &lit.text, e))
    }
}
