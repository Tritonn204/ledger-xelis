use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct ParsedTransfer {
    pub asset: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub extra_data_present: bool,
}

#[derive(Clone, Debug)]
pub struct ParsedBurn {
    pub asset: [u8; 32],
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub struct ParsedMultiSig {
    pub threshold: u8,
    pub participants_count: u8,
}

#[derive(Clone, Debug)]
pub struct ParsedContract {
    pub contract: [u8; 32],
    pub max_gas: u64,
    pub deposits_count: u8,
}

#[derive(Clone, Debug)]
pub enum XelisTxType {
    Transfer { 
        transfers: Vec<ParsedTransfer>,
        total_count: u8,
    },
    Burn(ParsedBurn),
    MultiSig(ParsedMultiSig),
    InvokeContract(ParsedContract),
    DeployContract { 
        has_constructor: bool,
        max_gas: u64,
    },
}

#[derive(Clone, Debug)]
pub struct ParsedTransaction {
    pub version: u8,
    pub source: [u8; 32],
    pub tx_type: XelisTxType,
    pub fee: u64,
    pub nonce: u64,
    pub total_size: usize,
}

// Transaction type constants (matching Xelis protocol)
pub const TX_BURN: u8 = 0;
pub const TX_TRANSFER: u8 = 1;
pub const TX_MULTISIG: u8 = 2;
pub const TX_INVOKE_CONTRACT: u8 = 3;
pub const TX_DEPLOY_CONTRACT: u8 = 4;