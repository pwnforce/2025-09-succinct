use sp1_sdk::{
    include_elf, utils, Elf, ProverClient, SP1Stdin,
};

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("test-simple-exec");

#[tokio::main]
async fn main() {
   // Setup logging.
   utils::setup_logger();

   // Create an input stream and write '500' to it.
   let n = 1000u32;

   // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
   // types of the elements in the input stream must match the types being read in the program.
   let mut stdin = SP1Stdin::new();
   stdin.write(&n);

   // Create a `ProverClient` method.
   let client = ProverClient::builder().cpu().build().await;

   // Execute the program using the `ProverClient.execute` method, without generating a proof.
   let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
   println!("executed program with {} cycles", report.total_instruction_count());
}
