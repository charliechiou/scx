mod bpf_skel;

use anyhow::{Context, Result};
use bpf_skel::*;

use libbpf_rs::skel::{OpenSkel as _, Skel as _, SkelBuilder as _};

use libbpf_rs::OpenObject;

use scx_utils::try_set_rlimit_infinity;

use std::mem::MaybeUninit;
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    /*
     * 1. 放寬 BPF 所需的 memory lock 限制。
     */
    try_set_rlimit_infinity();

    /*
     * 2. 準備存放 libbpf 打開的 BPF object。
     */
    let mut open_object = MaybeUninit::<OpenObject>::uninit();

    /*
     * 3. 建立由 build.rs 自動產生的 BPF skeleton builder。
     */
    let skel_builder = BpfSkelBuilder::default();

    /*
     * 4. Open BPF object。
     *
     * 這時還沒有真正 load 進 kernel。
     */
    let open_skel = skel_builder
        .open(&mut open_object)
        .context("Failed to open BPF object")?;

    /*
     * 5. Load BPF object 到 kernel。
     *
     * BPF verifier 會在這個階段驗證 BPF program。
     */
    let mut skel = open_skel.load().context("Failed to load BPF object")?;

    /*
     * 6. Attach 一般的 BPF programs。
     *
     * common.bpf.h 裡也可能包含 sched_ext 所需要的輔助 BPF program，
     * 因此先執行 skeleton 的 attach()。
     */
    skel.attach().context("Failed to attach BPF programs")?;

    /*
     * 7. Attach sched_ext struct_ops。
     *
     * 這一步完成後，mysched_ops 才真正註冊成 sched_ext scheduler。
     */
    let _struct_ops_link = skel
        .maps
        .mysched_ops
        .attach_struct_ops()
        .context("Failed to attach mysched_ops")?;

    println!("mysched is running");
    println!("Press Ctrl+C to stop");

    /*
     * 8. 讓 userspace loader 保持活著。
     *
     * _struct_ops_link 也因此持續存在。
     */
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
