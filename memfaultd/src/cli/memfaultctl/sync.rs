//
// Copyright (c) Memfault, Inc.
// See License.txt for details
use eyre::{eyre, Result};

use crate::util::ipc::send_flush_signal;

pub fn sync() -> Result<()> {
    match send_flush_signal() {
        Ok(()) => Ok(()),
        Err(e) => Err(eyre!(
            "Error: {} If you are not running memfaultd as a daemon you \
                             can force it to sync data with \
                             'killall -USR1 memfaultd'.",
            e
        )),
    }
}
