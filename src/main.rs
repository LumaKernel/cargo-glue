#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

use anyhow::Context as _;
use cargo_glue::{shell::Shell, Context, Opt};
use std::env;
use structopt::{clap, StructOpt};

fn main() {
    let mut shell = Shell::new();

    let result = (|| {
        let opt = Opt::from_iter_safe(env::args_os())?;

        let ctx = Context {
            cwd: env::current_dir().with_context(|| "could not get the current direcotry")?,
            cache_dir: dirs_next::cache_dir()
                .with_context(|| "could not find the cache directory")?
                .join("cargo-glue"),
            shell: &mut shell,
        };

        cargo_glue::run(opt, ctx)
    })();

    if let Err(err) = result {
        exit_with_error(err, &mut shell);
    }
}

fn exit_with_error(err: anyhow::Error, shell: &mut Shell) -> ! {
    if let Some(err) = err.downcast_ref::<clap::Error>() {
        err.exit();
    }

    let _ = shell.error(&err);

    for cause in err.chain().skip(1) {
        let _ = writeln!(shell.err(), "\nCaused by:");

        for line in cause.to_string().lines() {
            let _ = match line {
                "" => writeln!(shell.err()),
                line => writeln!(shell.err(), "  {}", line),
            };
        }
    }

    std::process::exit(1);
}
