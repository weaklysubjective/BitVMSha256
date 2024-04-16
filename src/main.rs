use std::env; // Import the necessary module

    const H_INIT: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const K: [u32; 64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

fn generate_sha256_script(message: &str) -> String {
    let mut script = String::new();
    
    // Constants for each round, typically used during the compression loop

    script += "// Push initial hash values onto the stack\n";
    for &h in H_INIT.iter().rev() {  // Assuming the last pushed is the first used
        script += &format!("{{u32_push(0x{:x})}}\n", h);
    }


    let msg_block = prepare_message_block(message);
    //print_msg_block(&msg_block);

    let mut w: [u32; 64] = [0; 64];
    w[..16].copy_from_slice(&msg_block);  // Initialize the first 16 words directly from the message block


    // Extend message schedule W[16] to W[63]
    script += "// Extend message schedule w[16] to w[63]\n";
    for t in 16..64 {
        script += &format!("// Calculate w[{}]\n", t);

        //println!("Sending {}", w[t-2]);
        script += &sigma1(w[t-2]);  // Passing the actual value directly
        script += &sigma0(w[t-15]); // Passing the actual value directly

        // Using actual values for u32_add
        script += &format!("{{u32_add(0x{:x}, 0x{:x})}}\n", w[t-7], w[t-16]); // Using values directly
 
    }

    script +=  &generate_sha256_compression_script() ; "// Insert the compression loop here using provided code\n";

    // Finalize updated hash values with initial values
    script += "// Finalize updated hash values with initial values\n";
    for i in 0..8 {
        script += &format!("{{u32_add(0x{:x}, 0x{:x})}} // Add final round results to initial hash value H_INIT[{}]\n", H_INIT[i], H_INIT[0], i);
    }

    script
}


fn generate_sha256_compression_script() -> String {
    let mut script = String::new();
    script += "// Initial hash values and W[t] should already be on the stack\n";

    // Constants for K already defined globally
    // const K: [u32; 64] = [ /* K values from SHA-256 spec */ ];
    // const H_INIT: [u32; 8] = [ /* Initial hash values a, b, c, d, e, f, g, h */ ];

    for t in 0..64 {
        script += &format!("// Round {}\n", t + 1);
        script += &format!("{{u32_push(0x{:x})}} // Push constant K[{}] value 0x{:x}\n", K[t], t, K[t]);
        
        // Assuming W[t] values are on the stack already, if not, they should be pushed similar to K[t]
        
        // Add K[t] and W[t]
        script += "{u32_add()} // Add K[t] and W[t]\n";

        // Compute Sigma1(e) and add to (K[t] + W[t])
        script += &sigma1(H_INIT[4]);  // e is at index 4 in H_INIT
        script += "{u32_add()} // Add result of sigma1(e) to (K[t] + W[t])\n";

        // Compute Ch(e, f, g) and add to previous sum
        script += &ch(H_INIT[4], H_INIT[5], H_INIT[6]);  // e, f, g are at indices 4, 5, 6 in H_INIT
        script += "{u32_add()} // Add result of Ch(e, f, g) to get T1\n";

        // Update hash value h with T1
        script += &format!("{{u32_push(0x{:x})}} // Push current hash value h\n", H_INIT[7]); // h is at index 7 in H_INIT
        script += "{u32_add()} // Add T1 to h to get the new h\n";

        // Compute Sigma0(a) and push result
        script += &sigma0(H_INIT[0]);  // a is at index 0 in H_INIT

        // Compute Maj(a, b, c) and add to Sigma0(a)
        script += &maj(H_INIT[0], H_INIT[1], H_INIT[2]);  // a, b, c are at indices 0, 1, 2 in H_INIT
        script += "{u32_add()} // Add Maj(a, b, c) to Sigma0(a) to get T2\n";

        // Update register a with T2
        script += &format!("{{u32_push(0x{:x})}} // Push current value of a\n", H_INIT[0]); // a is at index 0 in H_INIT
        script += "{u32_add()} // Add T2 to a to get the new a\n";

        // Prepare for next round using zip operations with H_INIT indices correctly assigned
        script += &format!("{{u32_zip(0x{:x}, 0x{:x})}} // Zip and prepare for next round\n", H_INIT[7], H_INIT[6]); // H_INIT[7] is 'h', H_INIT[6] is 'g'
        script += &format!("{{u32_zip(0x{:x}, 0x{:x})}}\n", H_INIT[6], H_INIT[5]); // 'g' and 'f'
        script += &format!("{{u32_zip(0x{:x}, 0x{:x})}}\n", H_INIT[5], H_INIT[4]); // 'f' and 'e'
        script += &format!("{{u32_zip(0x{:x}, 0x{:x})}}\n", H_INIT[4], H_INIT[3]); // 'e' and 'd'
        script += &format!("{{u32_zip(0x{:x}, 0x{:x})}}\n", H_INIT[3], H_INIT[2]); // 'd' and 'c'
        script += &format!("{{u32_zip(0x{:x}, 0x{:x})}}\n", H_INIT[2], H_INIT[1]); // 'c' and 'b'
        script += &format!("{{u32_zip(0x{:x}, 0x{:x})}}\n", H_INIT[1], H_INIT[0]); // 'b' and 'a'

    }

    script += "// Finalize hash values by combining with initial hash state\n";

    script
}



fn sigma1(x: u32) -> String {
    format!("{{
        u32_push(0x{:x})  // Push x
        u32_rrot(6)       // Rotate right by 6 bits
        u32_push(0x{:x})  // Push x again
        u32_rrot(11)      // Rotate right by 11 bits
        u32_xor()         // XOR the top two values on the stack
        u32_push(0x{:x})  // Push x again
        u32_rrot(25)      // Rotate right by 25 bits
        u32_xor()         // XOR the top two values on the stack
        u32_xor()         // XOR the top two values on the stack, result is sigma1
    }}\n", x, x, x)
}


fn sigma0(x: u32) -> String {
    format!("{{
        u32_push(0x{:x})  // Push x
        u32_rrot(7)       // Rotate right by 7 bits
        u32_push(0x{:x})  // Push x again
        u32_rrot(18)      // Rotate right by 18 bits
        u32_xor()         // XOR the top two values on the stack
        u32_push(0x{:x})  // Push x again
        u32_shr(3)        // Shift right by 3 bits (if u32_shr is available)
        u32_xor()         // XOR the top two values on the stack
        u32_xor()         // Final XOR for sigma0 result
    }}\n", x, x, x)
}

fn ch(x: u32, y: u32, z: u32) -> String {
    format!("{{
        u32_push(0x{:x})
        u32_push(0x{:x})
        u32_and()
        u32_push(0x{:x})
        u32_not()
        u32_push(0x{:x})
        u32_and()
        u32_xor()  // Ch result is on top of the stack
    }}\n", x, y, x, z)
}

fn maj(x: u32, y: u32, z: u32) -> String {
    format!("{{
        u32_push(0x{:x})
        u32_push(0x{:x})
        u32_and()
        u32_push(0x{:x})
        u32_push(0x{:x})
        u32_and()
        u32_push(0x{:x})
        u32_push(0x{:x})
        u32_and()
        u32_xor()
        u32_xor()  // Maj result is on top of the stack
    }}\n", x, y, x, z, y, z)
}


fn print_msg_block(msg_block: &[u32]) {
    println!("Message Block Contents:");
    for (index, value) in msg_block.iter().enumerate() {
        println!("w[{:02}]: 0x{:08x}", index, value);
    }
}


fn prepare_message_block(message: &str) -> [u32; 16] {
    let mut msg_bytes = message.as_bytes().to_vec();
    let bit_len = msg_bytes.len() * 8;

    // Append '1' bit and '0' padding
    msg_bytes.push(0x80); // '1' followed by many '0's
    while (msg_bytes.len() + 8) % 64 != 0 {
        msg_bytes.push(0);
    }

    // Append original length in bits as a 64-bit big-endian integer
    let bit_len_bytes = bit_len.to_be_bytes();
    msg_bytes.extend_from_slice(&bit_len_bytes);

    // Convert to array of u32; assuming little-endian for simplicity
    let mut msg_block = [0u32; 16];
    for (i, chunk) in msg_bytes.chunks(4).enumerate() {
        msg_block[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    msg_block
}


pub fn u32_not() -> String {
    let mut script = String::new();

    // Append the commands to the string
    script.push_str("OP_0xFFFFFFFF\n"); // Push the bitmask for a 32-bit integer (all bits set)
    script.push_str("OP_SWAP\n");       // Swap the top two elements on the stack
    script.push_str("OP_XOR\n");        // Perform XOR which simulates NOT

    script
}

pub fn u32_shr(n: u32) -> String {
    let mut script = String::new();

    // To divide by 2^n, we append OP_2DIV n times to the script.
    for _ in 0..n {
        script.push_str("OP_2DIV\n");
    }

    script
}



fn main() {
    let args: Vec<String> = env::args().collect(); // Collect arguments into a vector
    
    if args.len() < 2 {
        // Check if the message argument is provided
        println!("Usage: {} <message>", args[0]); // args[0] is the program name
        std::process::exit(1); // Exit if no argument is provided
    }

    let message = &args[1]; // The message will be the second item in args
    let generated_script = generate_sha256_script(message);
    println!("{}", generated_script);
    println!("Received message: {}", message);
}

