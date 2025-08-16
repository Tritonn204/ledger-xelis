/*****************************************************************************
 *   Ledger App Boilerplate Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#![no_std]
#![no_main]

mod crypto;
mod cx;
mod tx_types;
mod utils;
mod xlb;
mod app_ui {
    pub mod address;
    pub mod menu;
    pub mod sign;
}
mod handlers {
    #[cfg(debug_assertions)]
    pub mod debug_keys;
    pub mod get_public_key;
    pub mod get_version;
    pub mod sign_tx;
}

mod settings;

use app_ui::menu::ui_menu_main;
use handlers::{
    get_public_key::handler_get_public_key,
    get_version::handler_get_version,
    sign_tx::{handler_sign_tx, TxContext},
};
use ledger_device_sdk::io::{ApduHeader, Comm, Reply, StatusWords};
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

// Required for using String, Vec, format!...
extern crate alloc;

use ledger_device_sdk::nbgl::{init_comm, NbglReviewStatus, StatusType};

// P2 for last APDU to receive.
const P2_CHUNK_LAST: u8 = 0x00;
// P2 for more APDU to receive.
const P2_MORE_DATA: u8 = 0x80;
// P1 for first APDU number.
const P1_CHUNK_FIRST: u8 = 0x00;
// P1 for maximum APDU number.
const P1_CHUNK_MAX: u8 = 0xFF;

// Application status words.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq)]
pub enum AppSW {
    Deny = 0x6985,
    WrongP1P2 = 0x6A86,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    TxDisplayFail = 0xB001,
    AddrDisplayFail = 0xB002,
    TxWrongLength = 0xB004,
    TxParsingFail = 0xB005,
    TxHashFail = 0xB006,
    TxSignFail = 0xB008,
    KeyDeriveFail = 0xB009,
    VersionParsingFail = 0xB00A,
    WrongApduLength = StatusWords::BadLen as u16,
    MemoRequired = 0xB00C,
    MemoInvalid = 0xB00D,
    InvalidCommitment = 0xC000,
    BlindersRequired = 0xC001,
    InvalidCompressedRistretto = 0xC002,
    Ok = 0x9000,
    CryptoError = 0x6F00,
    AddressError = 0x6F01,
    ParamError = 0x6F02,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Reply {
        Reply(sw as u16)
    }
}

/// Possible input commands received through APDUs.
pub enum Instruction {
    GetVersion,
    GetAppName,
    GetPubkey {
        display: bool,
    },
    SignTx {
        chunk: u8,
        more: bool,
    },
    LoadMemo {
        chunk: u8,
        more: bool,
    },
    SendBlinders,
    #[cfg(debug_assertions)]
    DebugTestKeys,
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    /// APDU parsing logic.
    ///
    /// Parses INS, P1 and P2 bytes to build an [`Instruction`]. P1 and P2 are translated to
    /// strongly typed variables depending on the APDU instruction code. Invalid INS, P1 or P2
    /// values result in errors with a status word, which are automatically sent to the host by the
    /// SDK.
    ///
    /// This design allows a clear separation of the APDU parsing logic and commands handling.
    ///
    /// Note that CLA is not checked here. Instead the method [`Comm::set_expected_cla`] is used in
    /// [`sample_main`] to have this verification automatically performed by the SDK.
    fn try_from(value: ApduHeader) -> Result<Self, Self::Error> {
        match (value.ins, value.p1, value.p2) {
            (3, 0, 0) => Ok(Instruction::GetVersion),
            (4, 0, 0) => Ok(Instruction::GetAppName),
            (5, 0 | 1, 0) => Ok(Instruction::GetPubkey {
                display: value.p1 != 0,
            }),
            (6, P1_CHUNK_FIRST, P2_MORE_DATA)
            | (6, 1..=P1_CHUNK_MAX, P2_CHUNK_LAST | P2_MORE_DATA) => Ok(Instruction::SignTx {
                chunk: value.p1,
                more: value.p2 == P2_MORE_DATA,
            }),
            (0x10, P1_CHUNK_FIRST..=P1_CHUNK_MAX, P2_CHUNK_LAST | P2_MORE_DATA) => {
                Ok(Instruction::LoadMemo {
                    chunk: value.p1,
                    more: value.p2 == P2_MORE_DATA,
                })
            }
            (0x12, _, _) => Ok(Instruction::SendBlinders),
            #[cfg(debug_assertions)]
            (0xF0, _, _) => Ok(Instruction::DebugTestKeys),
            (3..=6 | 0x10 | 0x12, _, _) => Err(AppSW::WrongP1P2),
            (_, _, _) => Err(AppSW::InsNotSupported),
        }
    }
}

pub fn show_status_and_home_if_needed(
    _comm: &mut Comm,
    home: &mut NbglHomeAndSettings,
    ctx: &mut TxContext,
    ins: &Instruction,
    status: AppSW,
) {
    enum Action {
        Nothing,
        Status {
            ok: bool,
            ty: StatusType,
            go_home: bool,
            reset: bool,
        },
        Home {
            reset: bool,
        },
    }

    let action = match ins {
        // Memo step:
        Instruction::LoadMemo { more, .. } => {
            if *more {
                // Mid-stream, no UI needed
                Action::Nothing
            } else {
                // Last chunk - show result
                match status {
                    AppSW::Ok => Action::Home { reset: false },
                    AppSW::Deny => Action::Status {
                        ok: false,
                        ty: StatusType::Transaction,
                        go_home: true,
                        reset: true,
                    },
                    _ => Action::Nothing,
                }
            }
        }

        // Blinders step: no UI needed, just handle errors
        Instruction::SendBlinders => match status {
            AppSW::Ok => Action::Nothing, // Silent success
            _ => Action::Status {
                ok: false,
                ty: StatusType::Transaction,
                go_home: true,
                reset: true,
            },
        },

        // Signing step:
        Instruction::SignTx { .. } => {
            if ctx.sign_completed {
                let ok = (status == AppSW::Ok) && ctx.sign_succeeded;
                Action::Status {
                    ok,
                    ty: StatusType::Transaction,
                    go_home: true,
                    reset: true,
                }
            } else if status != AppSW::Ok {
                Action::Status {
                    ok: false,
                    ty: StatusType::Transaction,
                    go_home: true,
                    reset: true,
                }
            } else {
                Action::Nothing
            }
        }

        // Address display:
        Instruction::GetPubkey { display: true }
            if status == AppSW::Ok || status == AppSW::Deny =>
        {
            Action::Status {
                ok: status == AppSW::Ok,
                ty: StatusType::Address,
                go_home: true,
                reset: false,
            }
        }

        _ => Action::Nothing,
    };

    // Execute the chosen action
    match action {
        Action::Nothing => {}
        Action::Home { reset } => {
            home.show_and_return();
            if reset {
                ctx.reset();
            }
        }
        Action::Status {
            ok,
            ty,
            go_home,
            reset,
        } => {
            NbglReviewStatus::new().status_type(ty).show(ok);
            if go_home {
                home.show_and_return();
            }
            if reset {
                ctx.reset();
            }
        }
    }
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = Comm::new().set_expected_cla(0xe0);
    let mut tx_ctx = TxContext::new();

    init_comm(&mut comm);

    let mut home = ui_menu_main(&mut comm);
    home.show_and_return();

    loop {
        let ins: Instruction = comm.next_command();

        let status = match handle_apdu(&mut comm, &ins, &mut tx_ctx) {
            Ok(()) => {
                comm.reply_ok();
                AppSW::Ok
            }
            Err(sw) => {
                comm.reply(sw);
                sw
            }
        };

        show_status_and_home_if_needed(&mut comm, &mut home, &mut tx_ctx, &ins, status);
    }
}

fn handle_apdu(comm: &mut Comm, ins: &Instruction, ctx: &mut TxContext) -> Result<(), AppSW> {
    if !matches!(
        ins,
        Instruction::SignTx { .. } | Instruction::LoadMemo { .. } | Instruction::SendBlinders
    ) {
        ctx.reset();
    }

    match ins {
        Instruction::GetAppName => {
            comm.append(env!("CARGO_PKG_NAME").as_bytes());
            Ok(())
        }
        Instruction::GetVersion => handler_get_version(comm),
        Instruction::GetPubkey { display } => handler_get_public_key(comm, *display),
        Instruction::SignTx { chunk, more } => handler_sign_tx(comm, *chunk, *more, ctx),
        #[cfg(debug_assertions)]
        Instruction::DebugTestKeys => handlers::debug_keys::handler_debug_keys(comm),
        Instruction::LoadMemo { chunk, more } => {
            handlers::sign_tx::handler_load_memo(comm, *chunk, *more, ctx)
        }
        Instruction::SendBlinders => handlers::sign_tx::handler_send_blinders(comm, ctx),
    }
}
