use tfhe::shortint::prelude::*;

fn query(key: ServerKey, mut target: Ciphertext, inventory: &[(u8, u8)]) -> Ciphertext {
  let mut result = key.create_trivial(0);

  for (idx, cnt) in inventory {
    let mut item_equality = key.smart_scalar_equal(&mut target, *idx);
    let mut contribution = key.smart_scalar_mul(&mut item_equality, *cnt);
    result = key.smart_add(&mut result, &mut contribution);
  }
  
  result
}

fn main() {
  // nothing to do here
}

#[cfg(test)]
mod tests {
  use tfhe::shortint::prelude::*;
  use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0_KS_PBS;

  use crate::query;

  #[test]
  fn test_it() {
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_4_CARRY_0_KS_PBS);

    let item_code = 0u8;

    let item_code_ciphertext = client_key.encrypt(item_code as u64);

    assert_eq!(item_code as u64, client_key.decrypt(&item_code_ciphertext));

    let stock_ciphertext = query(server_key, item_code_ciphertext, &[
      (0, 2),
      (1, 1),
      (0, 1),
    ]);

    let stock_count = client_key.decrypt(&stock_ciphertext);

    assert_eq!(stock_count, 3);
  }
}
