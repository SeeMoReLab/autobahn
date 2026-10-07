# HotStuff

[![build status](https://img.shields.io/github/workflow/status/asonnino/hotstuff/Build/main?style=flat-square&logo=github)](https://github.com/asonnino/hotstuff/actions)
[![test status](https://img.shields.io/github/workflow/status/asonnino/hotstuff/Tests/main?style=flat-square&logo=github&label=tests)](https://github.com/asonnino/hotstuff/actions)
[![rustc](https://img.shields.io/badge/rustc-1.48+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

This repo provides a minimal implementation of the [HotStuff consensus protocol](https://arxiv.org/abs/1803.05069). The codebase has been designed to be small, efficient, and easy to benchmark and modify. It has not been designed to run in production but uses real cryptography ([dalek](https://doc.dalek.rs/ed25519_dalek)), networking ([tokio](https://docs.rs/tokio)), and storage ([rocksdb](https://docs.rs/rocksdb)).

## Running
This copy is driven by the adaptive-timer CloudLab harness (`scripts/cloudlab/run_hotstuff.sh` in the parent repository); the upstream Fabric benchmark scripts are not included.

## Next Steps
The [wiki](https://github.com/asonnino/hotstuff/wiki) documents the codebase, explains its architecture and how to read benchmarks' results, and provides a step-by-step tutorial to run [benchmarks on Amazon Web Services](https://github.com/asonnino/hotstuff/wiki/AWS-Benchmarks) accross multiple data centers (WAN).

## License
This software is licensed as [Apache 2.0](LICENSE).
