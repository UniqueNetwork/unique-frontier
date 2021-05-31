// SPDX-License-Identifier: Apache-2.0
// This file is part of Frontier.
//
// Copyright (c) 2020 Parity Technologies (UK) Ltd.
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

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;
use fp_evm::Precompile;
use evm::{ExitReason, ExitSucceed, ExitError, Context, executor::PrecompileOutput};
use frame_support::{dispatch::{Dispatchable, GetDispatchInfo, PostDispatchInfo}, weights::{Pays, DispatchClass}};
use pallet_evm::{AddressMapping, GasWeightMapping};
use codec::Decode;

pub struct Dispatch<T: pallet_evm::Config> {
	_marker: PhantomData<T>,
}

impl<T> Precompile for Dispatch<T> where
	T: pallet_evm::Config,
	T::Call: Dispatchable<PostInfo=PostDispatchInfo> + GetDispatchInfo + Decode,
	<T::Call as Dispatchable>::Origin: From<Option<T::AccountId>>,
{
	fn execute(
		input: &[u8],
		target_gas: Option<u64>,
		context: &Context,
	) -> PrecompileOutput {
		let call = match T::Call::decode(&mut &input[..]).map_err(|_| ExitError::Other("decode failed".into())) {
			Ok(call) => call,
			Err(e) => return e.into(),
		};
		let info = call.get_dispatch_info();

		let valid_call = info.pays_fee == Pays::Yes && info.class == DispatchClass::Normal;
		if !valid_call {
			return ExitError::Other("invalid call".into()).into()
		}

		if let Some(gas) = target_gas {
			let valid_weight = info.weight <= T::GasWeightMapping::gas_to_weight(gas);
			if !valid_weight {
				return ExitError::OutOfGas.into()
			}
		}

		let origin = T::AddressMapping::into_account_id(context.caller);

		match call.dispatch(Some(origin).into()) {
			Ok(post_info) => {
				let cost = T::GasWeightMapping::weight_to_gas(post_info.actual_weight.unwrap_or(info.weight));
				PrecompileOutput {
					exit_status: ExitReason::Succeed(ExitSucceed::Stopped),
					cost,
					output: Default::default(),
					logs: Default::default(),
				}
			},
			Err(_) => ExitError::Other("dispatch execution failed".into()).into(),
		}
	}
}
