# peload

![peload: Windows loader study](assets/project-mark.svg)

A Rust PE loader study derived from IronPE, with changes to error handling and PE directory handling.

Maintained by [unrandoms](https://github.com/unrandoms), derived from [iss4cf0ng/IronPE](https://github.com/iss4cf0ng/IronPE).

## Fork-specific work

- [`src/error.rs`](src/error.rs)
- [`src/loader.rs`](src/loader.rs)
- [`src/pe_structures.rs`](src/pe_structures.rs)

## Validation and limits

Windows-only loading behavior has not been validated here. The source should be treated as experimental, not production-ready.

This documentation update does not certify all inherited features. The [archived reference](UPSTREAM_README.md) describes the original ecosystem; its package names and release links may target upstream rather than this fork.

## Credits

See [CREDITS.md](CREDITS.md) for the distinction between the original implementation and this fork's adaptations. Original licenses and copyright notices remain in the repository.
