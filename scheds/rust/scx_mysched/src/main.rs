mod bpf_skel;

use anyhow::Result;
use bpf_skel::*;

use libbpf_rs::OpenObject;

use scx_utils::{
    scx_ops_attach,
    scx_ops_load,
    scx_ops_open,
    try_set_rlimit_infinity,
};

use std::mem::MaybeUninit;
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    /*
     * 放寬 BPF 所需的 memory lock 限制。
     */
    try_set_rlimit_infinity();

    /*
     * 準備存放 libbpf 打開的 BPF object。
     */
    let mut open_object = MaybeUninit::<OpenObject>::uninit();

    /*
     * 建立由 build.rs 自動產生的 BPF skeleton builder。
     */
    let skel_builder = BpfSkelBuilder::default();

    /*
     * 使用 scx_utils 開啟 sched_ext BPF skeleton。
     *
     * None 表示不提供額外的 libbpf open options。
     */
    let mut skel = scx_ops_open!(
        skel_builder,
        &mut open_object,
        mysched_ops,
        None
    )?;

    /*
     * Load BPF program。
     *
     * 這裡會經過 BPF verifier，
     * 並處理 scx 的 compatibility 與 UEI 設定。
     */
    let mut skel = scx_ops_load!(
        skel,
        mysched_ops,
        uei
    )?;

    /*
     * Attach scheduler。
     *
     * 內部會：
     *   1. skel.attach()
     *   2. mysched_ops.attach_struct_ops()
     */
    let _struct_ops_link = scx_ops_attach!(
        skel,
        mysched_ops
    )?;

    println!("mysched is running");
    println!("Press Ctrl+C to stop");

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
