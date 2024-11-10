mod license;

use crate::{process::ProcessBuilderExt as _, shell::Shell, toolchain, User};
use anyhow::{bail, Context as _};
use camino::{Utf8Path, Utf8PathBuf};
use cargo_metadata as cm;
use cargo_util::ProcessBuilder;
use if_chain::if_chain;
use indoc::indoc;
use itertools::Itertools as _;
use krates::cm as kcm;
use krates::PkgSpec;
use rand::Rng as _;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    io::Cursor,
    path::{Path, PathBuf},
    str,
};
use strum::EnumString;

pub(crate) fn locate_project(cwd: &Path) -> anyhow::Result<PathBuf> {
    cwd.ancestors()
        .map(|p| p.join("Cargo.toml"))
        .find(|p| p.exists())
        .with_context(|| {
            format!(
                "could not find `Cargo.toml` in `{}` or any parent directory",
                cwd.display(),
            )
        })
}

pub(crate) fn cargo_metadata(
    manifest_path: &Path,
    cwd: &Path,
) -> Result<kcm::Metadata, kcm::Error> {
    kcm::MetadataCommand::new()
        .manifest_path(manifest_path)
        .current_dir(cwd)
        .exec()
}

pub(crate) fn resolve_behavior(
    package: &kcm::Package,
    workspace_root: &Utf8Path,
) -> anyhow::Result<ResolveBehavior> {
    let cargo_toml = &cargo_util::paths::read(workspace_root.join("Cargo.toml").as_ref())?;
    let CargoToml { workspace } = toml::from_str(cargo_toml)?;
    return Ok(workspace
        .resolver
        .unwrap_or_else(|| package.edition().default_resolver_behavior()));

    #[derive(Deserialize)]
    struct CargoToml {
        #[serde(default)]
        workspace: Workspace,
    }

    #[derive(Default, Deserialize)]
    struct Workspace {
        resolver: Option<ResolveBehavior>,
    }
}

pub(crate) fn cargo_check_message_format_json(
    toolchain: &str,
    metadata: &kcm::Metadata,
    package: &kcm::Package,
    krate: &kcm::Target,
    shell: &mut Shell,
) -> anyhow::Result<Vec<cm::Message>> {
    let messages = ProcessBuilder::new(toolchain::rustup_exe(package.manifest_dir())?)
        .arg("run")
        .arg(toolchain)
        .arg("cargo")
        .arg("check")
        .arg("--message-format")
        .arg("json")
        .arg("-p")
        .arg(format!("{}:{}", package.name, package.version))
        .args(&krate.target_option())
        .cwd(&metadata.workspace_root)
        .try_inspect(|this| shell.status("Running", this))?
        .read_stdout::<Vec<u8>>()?;

    // TODO: check if ≧ 1.41.0

    cm::Message::parse_stream(Cursor::new(messages))
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

pub(crate) fn list_out_dirs<'cm>(
    metadata: &'cm kcm::Metadata,
    messages: &[cm::Message],
) -> BTreeMap<&'cm kcm::PackageId, Utf8PathBuf> {
    messages
        .iter()
        .flat_map(|message| match message {
            cm::Message::BuildScriptExecuted(cm::BuildScript {
                package_id,
                out_dir,
                ..
            }) => {
                let package_id = kcm::PackageId {
                    repr: package_id.repr.clone(),
                };
                Some((&metadata[&package_id].id, out_dir.clone()))
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn cargo_check_using_current_lockfile_and_cache(
    metadata: &kcm::Metadata,
    package: &kcm::Package,
    target: &kcm::Target,
    exclude: &[PkgSpec],
    code: &str,
) -> anyhow::Result<()> {
    let package_name = {
        let mut rng = rand::thread_rng();
        let suf = (0..16)
            .map(|_| match rng.gen_range(0..=35) {
                n @ 0..=25 => b'a' + n,
                n @ 26..=35 => b'0' + n - 26,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        let suf = str::from_utf8(&suf).expect("should be valid ASCII");
        format!("cargo-equip-check-output-{}", suf)
    };
    let crate_name = &*if target.is_lib() {
        package_name.replace('-', "_")
    } else {
        package_name.to_owned()
    };

    let temp_pkg = tempfile::Builder::new()
        .prefix(&package_name)
        .rand_bytes(0)
        .tempdir()?;

    let orig_manifest =
        cargo_util::paths::read(package.manifest_path.as_ref())?.parse::<toml_edit::Document>()?;

    let mut temp_manifest = indoc! {r#"
        [package]
        name = ""
        version = "0.0.0"
        edition = ""
    "#}
    .parse::<toml_edit::Document>()
    .unwrap();

    temp_manifest["package"]["name"] = toml_edit::value(package_name);
    temp_manifest["package"]["edition"] = toml_edit::value(package.edition.as_str());
    let mut tbl = toml_edit::Table::new();
    tbl["name"] = toml_edit::value(crate_name);
    tbl["path"] = toml_edit::value(format!("{}.rs", crate_name));
    if target.is_lib() {
        temp_manifest["lib"] = toml_edit::Item::Table(tbl);
    } else {
        temp_manifest[if target.is_example() {
            "example"
        } else {
            "bin"
        }] = toml_edit::Item::ArrayOfTables({
            let mut arr = toml_edit::ArrayOfTables::new();
            arr.push(tbl);
            arr
        });
    }
    temp_manifest["dependencies"] = orig_manifest["dependencies"].clone();
    temp_manifest["dev-dependencies"] = orig_manifest["dev-dependencies"].clone();

    let renames = package
        .dependencies
        .iter()
        .filter(|kcm::Dependency { kind, .. }| {
            [
                kcm::DependencyKind::Normal,
                kcm::DependencyKind::Development,
            ]
            .contains(kind)
        })
        .flat_map(|kcm::Dependency { rename, .. }| rename)
        .collect::<HashSet<_>>();

    let modify_dependencies = |table: &mut toml_edit::Table| {
        for name_in_toml in metadata
            .resolve
            .as_ref()
            .expect("`resolve` is `null`")
            .nodes
            .iter()
            .find(|kcm::Node { id, .. }| *id == package.id)
            .expect("should contain")
            .deps
            .iter()
            .filter(|kcm::NodeDep { pkg, .. }| !exclude.iter().any(|s| s.matches(&metadata[pkg])))
            .map(|kcm::NodeDep { name, pkg, .. }| {
                if renames.contains(&name) {
                    name
                } else {
                    &metadata[pkg].name
                }
            })
        {
            table.remove(name_in_toml);
        }

        for (_, value) in table.iter_mut() {
            if !value["path"].is_none() {
                if let toml_edit::Item::Value(value) = &mut value["path"] {
                    if let Some(possibly_rel_path) = value.as_str() {
                        *value = package
                            .manifest_dir()
                            .join(possibly_rel_path)
                            .into_string()
                            .into();
                    }
                }
            }
        }
    };

    if let toml_edit::Item::Table(table) = &mut temp_manifest["dependencies"] {
        modify_dependencies(table);
    }
    if let toml_edit::Item::Table(table) = &mut temp_manifest["dev-dependencies"] {
        modify_dependencies(table);
    }

    cargo_util::paths::write(
        temp_pkg.path().join("Cargo.toml"),
        temp_manifest.to_string(),
    )?;
    cargo_util::paths::copy(
        metadata.workspace_root.join("Cargo.lock"),
        temp_pkg.path().join("Cargo.lock"),
    )?;
    cargo_util::paths::write(temp_pkg.path().join(format!("{}.rs", crate_name)), code)?;

    ProcessBuilder::new(crate::process::cargo_exe()?)
        .arg("check")
        .arg("--target-dir")
        .arg(&metadata.target_directory)
        .arg("--manifest-path")
        .arg(temp_pkg.path().join("Cargo.toml"))
        .args(&if target.is_bin() {
            vec!["--bin", crate_name]
        } else if target.is_example() {
            vec!["--example", crate_name]
        } else {
            vec!["--lib"]
        })
        .arg("--offline")
        .cwd(&metadata.workspace_root)
        .exec()?;

    temp_pkg.close()?;
    Ok(())
}

pub(crate) trait MetadataExt {
    fn exactly_one_target(&self) -> anyhow::Result<(&kcm::Target, &kcm::Package)>;
    fn lib_target(&self) -> anyhow::Result<(&kcm::Target, &kcm::Package)>;
    fn bin_target_by_name<'a>(
        &'a self,
        name: &str,
    ) -> anyhow::Result<(&'a kcm::Target, &'a kcm::Package)>;
    fn example_target_by_name<'a>(
        &'a self,
        name: &str,
    ) -> anyhow::Result<(&'a kcm::Target, &'a kcm::Package)>;
    fn target_by_src_path<'a>(
        &'a self,
        src_path: &Path,
    ) -> anyhow::Result<(&'a kcm::Target, &'a kcm::Package)>;
    fn libs_to_bundle<'a>(
        &'a self,
        package_id: &'a kcm::PackageId,
        need_dev_deps: bool,
        cargo_udeps_outcome: &HashSet<String>,
        exclude: &[PkgSpec],
    ) -> anyhow::Result<BTreeMap<&'a kcm::PackageId, (&'a kcm::Target, String)>>;
    fn dep_lib_by_extern_crate_name(
        &self,
        package_id: &kcm::PackageId,
        extern_crate_name: &str,
    ) -> Option<&kcm::Package>;
    fn libs_with_extern_crate_names(
        &self,
        package_id: &kcm::PackageId,
        only: &HashSet<&kcm::PackageId>,
    ) -> anyhow::Result<BTreeMap<&kcm::PackageId, String>>;
}

impl MetadataExt for kcm::Metadata {
    fn exactly_one_target(&self) -> anyhow::Result<(&kcm::Target, &kcm::Package)> {
        let root_package = self.root_package();
        match (
            &*targets_in_ws(self)
                .filter(|(t, p)| {
                    (t.is_lib() || t.is_bin() || t.is_example())
                        && root_package.map_or(true, |r| r.id == p.id)
                })
                .collect::<Vec<_>>(),
            root_package,
        ) {
            ([], Some(root_package)) => {
                bail!("no lib/bin/example target in `{}`", root_package.name)
            }
            ([], None) => bail!("no lib/bin/example target in this workspace"),
            ([t], _) => Ok(*t),
            ([ts @ ..], _) => bail!(
                "could not determine which target to choose. Use the `--bin` option, `--example` \
                 option, `--lib` option, or `--src` option to specify a target.\n\
                 available targets: {}\n\
                 note: currently `cargo-equip` does not support the `default-run` manifest key.",
                ts.iter()
                    .map(|(target, _)| format!(
                        "{}{}",
                        &target.name,
                        if target.is_lib() {
                            " (lib)"
                        } else if target.is_bin() {
                            " (bin)"
                        } else if target.is_example() {
                            " (example)"
                        } else {
                            unreachable!()
                        }
                    ))
                    .format(", "),
            ),
        }
    }

    fn lib_target(&self) -> anyhow::Result<(&kcm::Target, &kcm::Package)> {
        let root_package = self.root_package();
        match (
            &*targets_in_ws(self)
                .filter(|(t, p)| t.is_lib() && root_package.map_or(true, |r| r.id == p.id))
                .collect::<Vec<_>>(),
            root_package,
        ) {
            ([], Some(root_package)) => {
                bail!("`{}` does not have a `lib` target", root_package.name)
            }
            ([], None) => bail!("no lib target in this workspace"),
            ([t], _) => Ok(*t),
            ([..], _) => bail!(
                "could not determine which library to choose. Use the `-p` option to specify a \
                 package.",
            ),
        }
    }

    fn bin_target_by_name<'a>(
        &'a self,
        name: &str,
    ) -> anyhow::Result<(&'a kcm::Target, &'a kcm::Package)> {
        target_by_kind_and_name(self, &kcm::TargetKind::Bin, name)
    }

    fn example_target_by_name<'a>(
        &'a self,
        name: &str,
    ) -> anyhow::Result<(&'a kcm::Target, &'a kcm::Package)> {
        target_by_kind_and_name(self, &kcm::TargetKind::Example, name)
    }

    fn target_by_src_path<'a>(
        &'a self,
        src_path: &Path,
    ) -> anyhow::Result<(&'a kcm::Target, &'a kcm::Package)> {
        match *targets_in_ws(self)
            .filter(|(t, _)| t.src_path == src_path)
            .collect::<Vec<_>>()
        {
            [] => bail!(
                "`{}` is not the main source file of any bin targets in this workspace ",
                src_path.display(),
            ),
            [bin] => Ok(bin),
            [..] => bail!(
                "multiple bin targets which `src_path` is `{}`",
                src_path.display(),
            ),
        }
    }

    fn libs_to_bundle<'a>(
        &'a self,
        package_id: &'a kcm::PackageId,
        need_dev_deps: bool,
        cargo_udeps_outcome: &HashSet<String>,
        exclude: &[PkgSpec],
    ) -> anyhow::Result<BTreeMap<&'a kcm::PackageId, (&'a kcm::Target, String)>> {
        let package = &self[package_id];

        let renames = package
            .dependencies
            .iter()
            .filter(|kcm::Dependency { kind, .. }| {
                [
                    kcm::DependencyKind::Normal,
                    kcm::DependencyKind::Development,
                ]
                .contains(kind)
            })
            .flat_map(|kcm::Dependency { rename, .. }| rename)
            .collect::<HashSet<_>>();

        let preds = {
            let rustc_exe = crate::process::cargo_exe()?
                .with_file_name("rustc")
                .with_extension(env::consts::EXE_EXTENSION);

            ProcessBuilder::new(rustc_exe)
                .args(&["--print", "cfg"])
                .cwd(package.manifest_path.with_file_name(""))
                .read_stdout::<String>()?
                .lines()
                .flat_map(cfg_expr::Expression::parse) // https://github.com/EmbarkStudios/cfg-expr/blob/25290dba689ce3f3ab589926ba545875f048c130/src/expr/parser.rs#L180-L195
                .collect::<Vec<_>>()
        };
        let preds = preds
            .iter()
            .flat_map(cfg_expr::Expression::predicates)
            .collect::<Vec<_>>();

        let kcm::Resolve { nodes, .. } = self
            .resolve
            .as_ref()
            .with_context(|| "`resolve` is `null`")?;
        let nodes = nodes.iter().map(|n| (&n.id, n)).collect::<HashMap<_, _>>();

        let satisfies = |node_dep: &kcm::NodeDep, accepts_dev: bool| -> _ {
            if node_dep.name == "proconio".to_owned() {
                let e = exclude
                    .iter()
                    .filter(|e| e.name == "proconio".to_string())
                    .collect::<Vec<_>>()
                    .get(0)
                    .cloned()
                    .unwrap();
                let krate = &self[&node_dep.pkg];
            }
            if exclude.iter().any(|s| s.matches(&self[&node_dep.pkg])) {
                return false;
            }

            let kcm::Node { features, .. } = &nodes[&node_dep.pkg];
            let features = features.iter().map(|s| &**s).collect::<HashSet<_>>();

            node_dep
                .dep_kinds
                .iter()
                .any(|kcm::DepKindInfo { kind, target, .. }| {
                    (*kind == kcm::DependencyKind::Normal
                        || accepts_dev && *kind == kcm::DependencyKind::Development)
                        && target
                            .as_ref()
                            .and_then(|target| {
                                cfg_expr::Expression::parse(&target.to_string()).ok()
                            })
                            .map_or(true, |target| {
                                target.eval(|pred| match pred {
                                    cfg_expr::Predicate::Feature(feature) => {
                                        features.contains(feature)
                                    }
                                    pred => preds.contains(pred),
                                })
                            })
                })
        };

        if nodes[package_id]
            .deps
            .iter()
            .any(|kcm::NodeDep { dep_kinds, .. }| dep_kinds.is_empty())
        {
            bail!("this tool requires Rust 1.41+ for calculating dependencies");
        }

        let mut deps = nodes[package_id]
            .deps
            .iter()
            .filter(|node_dep| {
                let s = satisfies(node_dep, need_dev_deps);
                s
            })
            .flat_map(|node_dep| {
                let lib_package = &self[&node_dep.pkg];
                let lib_target =
                    lib_package
                        .targets
                        .iter()
                        .find(|kcm::Target { kind, .. }| {
                            *kind == [kcm::TargetKind::Lib] || *kind == [kcm::TargetKind::ProcMacro]
                        })?;
                let (lib_extern_crate_name, lib_name_in_toml) = if renames.contains(&node_dep.name)
                {
                    (node_dep.name.clone(), &node_dep.name)
                } else {
                    (lib_target.crate_name(), &lib_package.name)
                };
                if cargo_udeps_outcome.contains(lib_name_in_toml) {
                    return None;
                }
                Some((&lib_package.id, (lib_target, lib_extern_crate_name)))
            })
            .chain(
                package
                    .lib_like_target()
                    .map(|lib_target| (package_id, (lib_target, lib_target.crate_name()))),
            )
            .collect::<BTreeMap<_, _>>();

        let all_package_ids = &mut deps.keys().copied().collect::<HashSet<_>>();
        let all_extern_crate_names = &mut deps
            .values()
            .map(|(_, s)| s.clone())
            .collect::<HashSet<_>>();

        while {
            let next = deps
                .iter()
                .filter(|(_, (kcm::Target { kind, .. }, _))| *kind == [kcm::TargetKind::Lib])
                .map(|(package_id, _)| nodes[package_id])
                .flat_map(|kcm::Node { deps, .. }| deps)
                .filter(|node_dep| {
                    satisfies(node_dep, false) && all_package_ids.insert(&node_dep.pkg)
                })
                .flat_map(|kcm::NodeDep { pkg, .. }| {
                    let package = &self[pkg];
                    let target = package.targets.iter().find(|kcm::Target { kind, .. }| {
                        *kind == [kcm::TargetKind::Lib] || *kind == [kcm::TargetKind::ProcMacro]
                    })?;
                    let mut extern_crate_name = format!(
                        "__{}_{}",
                        package.name.replace('-', "_"),
                        package
                            .version
                            .to_string()
                            .replace(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9'), "_"),
                    );
                    while !all_extern_crate_names.insert(extern_crate_name.clone()) {
                        extern_crate_name += "_";
                    }
                    Some((&package.id, (target, extern_crate_name)))
                })
                .collect::<Vec<_>>();
            let next_is_empty = next.is_empty();
            deps.extend(next);
            !next_is_empty
        } {}

        Ok(deps)
    }

    fn dep_lib_by_extern_crate_name(
        &self,
        package_id: &kcm::PackageId,
        extern_crate_name: &str,
    ) -> Option<&kcm::Package> {
        // https://docs.rs/cargo/0.47.0/src/cargo/core/resolver/resolve.rs.html#323-352

        let package = &self[package_id];

        let node = self
            .resolve
            .as_ref()
            .into_iter()
            .flat_map(|kcm::Resolve { nodes, .. }| nodes)
            .find(|kcm::Node { id, .. }| id == package_id)?;

        let found_explicitly_renamed_one = package
            .dependencies
            .iter()
            .flat_map(|kcm::Dependency { rename, .. }| rename)
            .any(|rename| rename == extern_crate_name);

        if found_explicitly_renamed_one {
            Some(
                &self[&node
                    .deps
                    .iter()
                    .find(|kcm::NodeDep { name, .. }| name == extern_crate_name)
                    .expect("found the dep in `dependencies`, not in `resolve.deps`")
                    .pkg],
            )
        } else {
            node.dependencies
                .iter()
                .map(|dep_id| &self[dep_id])
                .flat_map(|p| p.targets.iter().map(move |t| (t, p)))
                .find(|(t, _)| {
                    t.crate_name() == extern_crate_name
                        && (t.is_lib() || t.is_proc_macro())
                })
                .map(|(_, p)| p)
                .or_else(|| {
                    matches!(package.lib_like_target(), Some(t) if t.crate_name() == extern_crate_name)
                        .then(|| package)
                })
        }
    }

    fn libs_with_extern_crate_names(
        &self,
        package_id: &kcm::PackageId,
        only: &HashSet<&kcm::PackageId>,
    ) -> anyhow::Result<BTreeMap<&kcm::PackageId, String>> {
        let package = &self[package_id];

        let renames = package
            .dependencies
            .iter()
            .flat_map(|kcm::Dependency { rename, .. }| rename)
            .collect::<HashSet<_>>();

        let kcm::Resolve { nodes, .. } =
            self.resolve.as_ref().with_context(|| "`resolve` is null")?;

        let kcm::Node { deps, .. } = nodes
            .iter()
            .find(|kcm::Node { id, .. }| id == package_id)
            .with_context(|| "could not find the node")?;

        Ok(deps
            .iter()
            .filter(|kcm::NodeDep { pkg, dep_kinds, .. }| {
                matches!(
                    &**dep_kinds,
                    [kcm::DepKindInfo {
                        kind: kcm::DependencyKind::Normal,
                        ..
                    }]
                ) && only.contains(pkg)
            })
            .flat_map(|kcm::NodeDep { name, pkg, .. }| {
                let extern_crate_name = if renames.contains(name) {
                    name.clone()
                } else {
                    self[pkg]
                        .targets
                        .iter()
                        .find(|target| target.is_lib() || target.is_proc_macro())?
                        .crate_name()
                };
                Some((pkg, extern_crate_name))
            })
            .collect())
    }
}

fn target_by_kind_and_name<'a>(
    metadata: &'a kcm::Metadata,
    kind: &kcm::TargetKind,
    name: &str,
) -> anyhow::Result<(&'a kcm::Target, &'a kcm::Package)> {
    match *targets_in_ws(metadata)
        .filter(|(t, _)| t.name == name && t.kind == [kind.to_owned()])
        .collect::<Vec<_>>()
    {
        [] => bail!("no {} target named `{}`", format!("{:?}", kind), name),
        [target] => Ok(target),
        [..] => bail!(
            "multiple {} targets named `{}` in this workspace",
            format!("{:?}", kind),
            name,
        ),
    }
}

fn targets_in_ws(metadata: &kcm::Metadata) -> impl Iterator<Item = (&kcm::Target, &kcm::Package)> {
    metadata
        .packages
        .iter()
        .filter(move |kcm::Package { id, .. }| metadata.workspace_members.contains(id))
        .flat_map(|p| p.targets.iter().map(move |t| (t, p)))
}

pub(crate) trait PackageExt {
    fn has_custom_build(&self) -> bool;
    fn has_lib(&self) -> bool;
    fn has_proc_macro(&self) -> bool;
    fn lib_like_target(&self) -> Option<&kcm::Target>;
    fn manifest_dir(&self) -> &Utf8Path;
    fn edition(&self) -> Edition;
    fn read_license_text(&self, mine: &[User], cache_dir: &Path) -> anyhow::Result<Option<String>>;
}

impl PackageExt for kcm::Package {
    fn has_custom_build(&self) -> bool {
        self.targets.iter().any(TargetExt::is_custom_build)
    }

    fn has_lib(&self) -> bool {
        self.targets.iter().any(TargetExt::is_lib)
    }

    fn has_proc_macro(&self) -> bool {
        self.targets.iter().any(TargetExt::is_proc_macro)
    }

    fn lib_like_target(&self) -> Option<&kcm::Target> {
        self.targets
            .iter()
            .find(|target| target.is_lib() || target.is_proc_macro())
    }

    fn manifest_dir(&self) -> &Utf8Path {
        self.manifest_path.parent().expect("should not be empty")
    }

    fn edition(&self) -> Edition {
        self.edition
            .as_str()
            .parse()
            .expect("`edition` modified invalidly")
    }

    fn read_license_text(&self, mine: &[User], cache_dir: &Path) -> anyhow::Result<Option<String>> {
        license::read_non_unlicense_license_file(self, mine, cache_dir)
    }
}

pub(crate) trait PackageIdExt {
    fn mask_path(&self) -> String;
}

impl PackageIdExt for kcm::PackageId {
    fn mask_path(&self) -> String {
        if_chain! {
            if let [s1, s2] = *self.repr.split(" (path+").collect::<Vec<_>>();
            if s2.ends_with(')');
            then {
                format!(
                    "{} (path+{})",
                    s1,
                    s2.chars().map(|_| '█').collect::<String>(),
                )
            } else {
                self.repr.clone()
            }
        }
    }
}

pub(crate) trait TargetExt {
    fn is_bin(&self) -> bool;
    fn is_example(&self) -> bool;
    fn is_custom_build(&self) -> bool;
    fn is_lib(&self) -> bool;
    fn is_proc_macro(&self) -> bool;
    fn crate_name(&self) -> String;
    fn target_option(&self) -> Vec<&str>;
}

impl TargetExt for kcm::Target {
    fn is_bin(&self) -> bool {
        self.kind == [kcm::TargetKind::Bin]
    }

    fn is_example(&self) -> bool {
        self.kind == [kcm::TargetKind::Example]
    }

    fn is_custom_build(&self) -> bool {
        self.kind == [kcm::TargetKind::CustomBuild]
    }

    fn is_lib(&self) -> bool {
        self.kind == [kcm::TargetKind::Lib]
    }

    fn is_proc_macro(&self) -> bool {
        self.kind == [kcm::TargetKind::ProcMacro]
    }

    fn crate_name(&self) -> String {
        self.name.replace('-', "_")
    }

    fn target_option(&self) -> Vec<&str> {
        if self.is_lib() {
            vec!["--lib"]
        } else if self.is_example() {
            vec!["--example", &self.name]
        } else {
            vec!["--bin", &self.name]
        }
    }
}

trait SourceExt {
    fn rev_git(&self) -> Option<(&str, &str)>;
}

impl SourceExt for kcm::Source {
    fn rev_git(&self) -> Option<(&str, &str)> {
        let url = self.repr.strip_prefix("git+")?;
        match *url.split('#').collect::<Vec<_>>() {
            [url, rev] => Some((url, rev)),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, EnumString)]
pub(crate) enum Edition {
    #[strum(serialize = "2015")]
    Edition2015,
    #[strum(serialize = "2018")]
    Edition2018,
    #[strum(serialize = "2021")]
    Edition2021,
}

impl Edition {
    fn default_resolver_behavior(self) -> ResolveBehavior {
        match self {
            Self::Edition2015 | Self::Edition2018 => ResolveBehavior::V1,
            Self::Edition2021 => ResolveBehavior::V2,
        }
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Deserialize)]
pub(crate) enum ResolveBehavior {
    #[serde(rename = "1")]
    V1,
    #[serde(rename = "2")]
    V2,
}
