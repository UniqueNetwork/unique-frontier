// SPDX-License-Identifier: Apache-2.0
// This file is part of Frontier.
//
// Copyright (c) 2017-2020 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use frame_support::{
	dispatch::{DispatchInfo, GetDispatchInfo},
	traits::{ExtrinsicCall, InherentBuilder, SignedTransactionBuilder},
};
use scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{
	generic::Preamble,
	traits::{
		self, Checkable, Dispatchable, ExtrinsicLike, ExtrinsicMetadata, IdentifyAccount, MaybeDisplay, Member, TransactionExtension
	},
	transaction_validity::{InvalidTransaction, TransactionValidityError},
	OpaqueExtrinsic, RuntimeDebug,
};

use crate::{CheckedExtrinsic, CheckedFormat, SelfContainedCall};

/// A extrinsic right from the external world. This is unchecked and so
/// can contain a signature.
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct UncheckedExtrinsic<Address, Call, Signature, Extra>(
	pub sp_runtime::generic::UncheckedExtrinsic<Address, Call, Signature, Extra>,
);

impl<Address, Call, Signature, Extension> UncheckedExtrinsic<Address, Call, Signature, Extension> {
	/// New instance of a bare (ne unsigned) extrinsic. This could be used for an inherent or an
	/// old-school "unsigned transaction" (which are new being deprecated in favour of general
	/// transactions).
	#[deprecated = "Use new_bare instead"]
	pub fn new_unsigned(function: Call) -> Self {
		Self::new_bare(function)
	}

	/// Returns `true` if this extrinsic instance is an inherent, `false`` otherwise.
	pub fn is_inherent(&self) -> bool {
		self.0.is_inherent()
	}

	/// Returns `true` if this extrinsic instance is an old-school signed transaction, `false`
	/// otherwise.
	pub fn is_signed(&self) -> bool {
		self.0.is_signed()
	}

	/// Create an `UncheckedExtrinsic` from a `Preamble` and the actual `Call`.
	pub fn from_parts(function: Call, preamble: Preamble<Address, Signature, Extension>) -> Self {
		Self(sp_runtime::generic::UncheckedExtrinsic { preamble, function })
	}

	/// New instance of a bare (ne unsigned) extrinsic.
	pub fn new_bare(function: Call) -> Self {
		Self(sp_runtime::generic::UncheckedExtrinsic::new_bare(function))
	}

	/// New instance of a bare (ne unsigned) extrinsic on extrinsic format version 4.
	pub fn new_bare_legacy(function: Call) -> Self {
		Self(sp_runtime::generic::UncheckedExtrinsic::new_bare_legacy(function))
	}

	/// New instance of an old-school signed transaction on extrinsic format version 4.
	pub fn new_signed(
		function: Call,
		signed: Address,
		signature: Signature,
		tx_ext: Extension,
	) -> Self {
		Self(sp_runtime::generic::UncheckedExtrinsic::new_signed(function, signed, signature, tx_ext))
	}

	/// New instance of an new-school unsigned transaction.
	pub fn new_transaction(function: Call, tx_ext: Extension) -> Self {
		Self(sp_runtime::generic::UncheckedExtrinsic::new_transaction(function, tx_ext))
	}
}

impl<Address, Call, Signature, Extension> ExtrinsicLike
	for UncheckedExtrinsic<Address, Call, Signature, Extension>
where
	Address: TypeInfo,
	Call: TypeInfo + SelfContainedCall,
	Signature: TypeInfo,
	Extension: TypeInfo
{
	fn is_signed(&self) -> Option<bool> {
		if self.0.function.is_self_contained() {
			Some(true)
		} else {
			#[allow(deprecated)]
			ExtrinsicLike::is_signed(&self.0)
		}
	}
}

// impl<Address, AccountId, Call, Signature, Extension, Lookup> Checkable<ChainContext<Runtime>> for UncheckedExtrinsic<Address, Call, Signature, Extension> {

// }

impl<Address, AccountId, Call, Signature, Extension, Lookup> Checkable<Lookup>
	for UncheckedExtrinsic<Address, Call, Signature, Extension>
where
	Address: Member + MaybeDisplay,
	Call: Encode + Member + SelfContainedCall,
	Signature: Member + traits::Verify,
	<Signature as traits::Verify>::Signer: IdentifyAccount<AccountId = AccountId>,
	Extension: TransactionExtension<Call>,
	AccountId: Member + MaybeDisplay,
	Lookup: traits::Lookup<Source = Address, Target = AccountId>,
{
	type Checked =
		CheckedExtrinsic<AccountId, Call, Extension, <Call as SelfContainedCall>::SignedInfo>;

	fn check(self, lookup: &Lookup) -> Result<Self::Checked, TransactionValidityError> {
		if self.0.function.is_self_contained() {
			if self.0.is_signed() {
				return Err(TransactionValidityError::Invalid(
					InvalidTransaction::BadProof,
				));
			}

			let signed_info = self.0.function.check_self_contained().ok_or(
				TransactionValidityError::Invalid(InvalidTransaction::BadProof),
			)??;
			Ok(CheckedExtrinsic {
				format: CheckedFormat::SelfContained(signed_info),
				function: self.0.function,
			})
		} else {
			let checked = Checkable::<Lookup>::check(self.0, lookup)?;
			Ok(CheckedExtrinsic {
				format: match checked.format {
						sp_runtime::generic::ExtrinsicFormat::Bare => CheckedFormat::Bare,
						sp_runtime::generic::ExtrinsicFormat::Signed(account_id, extension) => CheckedFormat::Signed(account_id, extension),
						sp_runtime::generic::ExtrinsicFormat::General(_, extension) => CheckedFormat::General(extension),
					},
				function: checked.function,
			})
		}
	}

	#[cfg(feature = "try-runtime")]
	fn unchecked_into_checked_i_know_what_i_am_doing(
		self,
		lookup: &Lookup,
	) -> Result<Self::Checked, TransactionValidityError> {
		if self.0.function.is_self_contained() {
			match self.0.function.check_self_contained() {
				Some(signed_info) => Ok(CheckedExtrinsic {
					format: match signed_info {
						Ok(info) => CheckedFormat::SelfContained(info),
						_ => CheckedFormat::Bare,
					},
					function: self.0.function,
				}),
				None => Ok(CheckedExtrinsic {
					format: CheckedFormat::Bare,
					function: self.0.function,
				}),
			}
		} else {
			let checked =
				Checkable::<Lookup>::unchecked_into_checked_i_know_what_i_am_doing(self.0, lookup)?;
			Ok(CheckedExtrinsic {
				format: match checked.format {
					sp_runtime::generic::ExtrinsicFormat::Bare => CheckedFormat::Bare,
					sp_runtime::generic::ExtrinsicFormat::Signed(account_id, extension) => CheckedFormat::Signed(account_id, extension),
					sp_runtime::generic::ExtrinsicFormat::General(_, extension) => CheckedFormat::General(extension),
				},
				function: checked.function,
			})
		}
	}
}

impl<Address, Call, Signature, Extension> ExtrinsicMetadata
	for UncheckedExtrinsic<Address, Call, Signature, Extension>
where
	Call: Dispatchable,
	Extension: TransactionExtension<Call>
{
	const VERSIONS: &'static [u8] = <sp_runtime::generic::UncheckedExtrinsic<Address, Call, Signature, Extension> as ExtrinsicMetadata>::VERSIONS;
	type TransactionExtensions = Extension;
}

impl<Address, Call, Signature, Extra> ExtrinsicCall
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: TypeInfo,
	Call: SelfContainedCall + TypeInfo,
	Signature: TypeInfo,
	Extra: TypeInfo,
{
	type Call = Call;
	
	fn call(&self) -> &Self::Call {
		&self.0.function
	}
}

impl<Address, Call: GetDispatchInfo, Signature, Extra> GetDispatchInfo
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Extra: TypeInfo,
{
	fn get_dispatch_info(&self) -> DispatchInfo {
		self.0.function.get_dispatch_info()
	}
}

#[cfg(feature = "serde")]
impl<Address: Encode, Signature: Encode, Call: Encode, Extra: Encode> serde::Serialize
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
{
	fn serialize<S>(&self, seq: S) -> Result<S::Ok, S::Error>
	where
		S: ::serde::Serializer,
	{
		self.0.serialize(seq)
	}
}

#[cfg(feature = "serde")]
impl<'a, Address: Decode, Signature: Decode, Call: Decode, Extra: Decode>
	serde::Deserialize<'a> for UncheckedExtrinsic<Address, Call, Signature, Extra>
{
	fn deserialize<D>(de: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'a>,
	{
		<sp_runtime::generic::UncheckedExtrinsic<Address, Call, Signature, Extra>>::deserialize(de)
			.map(Self)
	}
}

impl<Address, Call, Signature, Extra> From<UncheckedExtrinsic<Address, Call, Signature, Extra>>
	for OpaqueExtrinsic
where
	Address: Encode,
	Signature: Encode,
	Call: Encode,
	Extra: Encode,
{
	fn from(extrinsic: UncheckedExtrinsic<Address, Call, Signature, Extra>) -> Self {
		extrinsic.0.into()
	}
}

impl<Address, Call, Signature, Extension> SignedTransactionBuilder
	for UncheckedExtrinsic<Address, Call, Signature, Extension>
where
	Address: TypeInfo,
	Call: TypeInfo + SelfContainedCall,
	Signature: TypeInfo,
	Extension: TypeInfo,
{
	type Address = Address;
	type Signature = Signature;
	type Extension = Extension;

	fn new_signed_transaction(
		call: Self::Call,
		signed: Address,
		signature: Signature,
		tx_ext: Extension,
	) -> Self {
		Self::new_signed(call, signed, signature, tx_ext)
	}
}

impl<Address, Call, Signature, Extra> InherentBuilder
	for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
	Address: TypeInfo,
	Call: TypeInfo + SelfContainedCall,
	Signature: TypeInfo,
	Extra: TypeInfo,
{
	fn new_inherent(call: Self::Call) -> Self {
		Self::new_bare(call)
	}
}
