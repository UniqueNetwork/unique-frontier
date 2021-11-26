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

pub use evm::{
	executor::stack::{PrecompileFailure, PrecompileFn, PrecompileOutput},
	Context, ExitError, ExitSucceed,
};
use impl_trait_for_tuples::impl_for_tuples;
use sp_core::H160;
use sp_std::vec::Vec;

pub type PrecompileResult = Result<PrecompileOutput, PrecompileFailure>;

pub trait StaticPrecompileSet {
	fn execute(
		address: H160,
		input: &[u8],
		target_gas: Option<u64>,
		context: &Context,
		is_static: bool,
	) -> Option<PrecompileResult>;

	fn is_precompile(address: H160) -> bool;
}

impl StaticPrecompileSet for () {
	fn execute(
		_address: H160,
		_input: &[u8],
		_target_gas: Option<u64>,
		_context: &Context,
		_is_static: bool,
	) -> Option<PrecompileResult> {
		None
	}

	fn is_precompile(_address: H160) -> bool {
		false
	}
}

#[impl_for_tuples(1, 12)]
#[tuple_types_custom_trait_bound(Precompile)]
impl StaticPrecompileSet for Tuple {
	fn execute(
		address: H160,
		input: &[u8],
		target_gas: Option<u64>,
		context: &Context,
		is_static: bool,
	) -> Option<PrecompileResult> {
		let mut index = 0;
		for_tuples!(#(
			index += 1;
			if address == H160::from_low_u64_be(index) {
				return Some(<Tuple as Precompile>::execute(input, target_gas, context, is_static))
			}
		)*);
		None
	}

	fn is_precompile(address: H160) -> bool {
		let mut index = 0;
		for_tuples!(#(
			index += 1;
			if address == H160::from_low_u64_be(index) {
				return true
			}
		)*);
		false
	}
}

pub trait Precompile {
	// Implements PrecompileFn
	fn execute(
		input: &[u8],
		target_gas: Option<u64>,
		context: &Context,
		is_static: bool,
	) -> PrecompileResult;
}

pub trait LinearCostPrecompile {
	const BASE: u64;
	const WORD: u64;

	fn execute(input: &[u8], cost: u64) -> core::result::Result<(ExitSucceed, Vec<u8>), ExitError>;
}

impl<T: LinearCostPrecompile> Precompile for T {
	fn execute(input: &[u8], target_gas: Option<u64>, _: &Context, _: bool) -> PrecompileResult {
		let cost = match ensure_linear_cost(target_gas, input.len() as u64, T::BASE, T::WORD) {
			Ok(cost) => cost,
			Err(exit_status) => return Err(PrecompileFailure::Error { exit_status }),
		};

		Self::execute(input, cost)
			.map(|(exit_status, output)| PrecompileOutput {
				exit_status,
				cost,
				output,
				logs: Vec::new(),
			})
			.map_err(|exit_status| PrecompileFailure::Error { exit_status })
	}
}

/// Linear gas cost
fn ensure_linear_cost(
	target_gas: Option<u64>,
	len: u64,
	base: u64,
	word: u64,
) -> Result<u64, ExitError> {
	let cost = base
		.checked_add(
			word.checked_mul(len.saturating_add(31) / 32)
				.ok_or(ExitError::OutOfGas)?,
		)
		.ok_or(ExitError::OutOfGas)?;

	if let Some(target_gas) = target_gas {
		if cost > target_gas {
			return Err(ExitError::OutOfGas);
		}
	}

	Ok(cost)
}
