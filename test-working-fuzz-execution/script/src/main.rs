use sp1_sdk::{
    include_elf, utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey,
    SP1ProofWithPublicValues, SP1Stdin,
};

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("test-working-fuzz");

#[tokio::main]
async fn main() {
    // Setup logging.
    utils::setup_logger();

    println!("🧪 Testing assembly program: test-working-fuzz");
    println!("📋 Instructions: 8");

    // Create an input stream (empty for our assembly test)
    let stdin = SP1Stdin::new();

    // Create a `ProverClient` method.
    let client = ProverClient::builder().cpu().build().await;

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
    println!("✅ Program executed successfully!");
    println!("📊 Executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given program and input.
    let pk = client.setup(ELF).await.unwrap();
    let mut proof = client.prove(&pk, stdin.clone()).core().await.unwrap();

    println!("generated proof");
}
