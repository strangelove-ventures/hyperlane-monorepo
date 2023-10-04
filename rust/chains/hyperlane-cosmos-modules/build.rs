fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .compile(&[
            "proto/mailbox/query.proto",
            "proto/mailbox/tx.proto",
            "proto/ism/legacy_multisig.proto",
            "proto/ism/merkle_root_multisig.proto",
            "proto/ism/message_id_multisig.proto",
            "proto/ism/query.proto",
            ], &["proto"])
        .unwrap();
    Ok(())
}