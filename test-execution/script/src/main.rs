use sp1_sdk::{
    include_elf, utils, Elf, ProverClient, SP1Stdin, Prover,
};

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("test");

#[tokio::main]
async fn main() {
    // Setup logging.
    utils::setup_logger();

    println!("🧪 Testing assembly program: test");
    println!("📋 Instructions: 8");

    // Create an input stream (empty for our assembly test)
    let stdin = SP1Stdin::new();

    // Create a `ProverClient` method.
    let client = ProverClient::builder().cpu().build().await;

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
    println!("✅ Program executed successfully!");
    println!("📊 Executed program with {} cycles", report.total_instruction_count());
}
