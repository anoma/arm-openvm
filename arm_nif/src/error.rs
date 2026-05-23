use bincode::error::DecodeError;
use rustler::{Encoder, Env, Term};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArmNifError {
    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] DecodeError),
    #[error("ARM error: {0}")]
    Arm(#[from] arm_core::error::ArmError),
}

impl Encoder for ArmNifError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

impl From<ArmNifError> for rustler::Error {
    fn from(e: ArmNifError) -> Self {
        rustler::Error::Term(Box::new(e))
    }
}
