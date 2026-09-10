//! Prints the reference's tagged-CBOR `Compressed` bytes for a fixed input so
//! the TypeScript suite can verify that it decompresses miniz_oxide output.
use bc_components::Compressed;
use dcbor::prelude::*;

fn main() {
    bc_components::register_tags();
    let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(4);
    let c = Compressed::from_decompressed_data(text.as_bytes(), None);
    println!("{}", hex::encode(c.tagged_cbor_data()));
}
