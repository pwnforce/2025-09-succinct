#!/usr/bin/env python3
"""
Simple Assembly Instruction Generator for SP1 Fuzzing
Uses JSON instead of YAML for better compatibility
"""

import json
import sys
import os
import argparse
import shutil
import time
from pathlib import Path

class SimpleAssemblyGenerator:
    def __init__(self, json_file: str, template_file: str):
        self.json_file = json_file
        self.template_file = template_file
        self.instructions = []
        self.config = {}
        self.setup = {}
        
    def load_json(self):
        """Load and parse the JSON instruction file"""
        try:
            with open(self.json_file, 'r') as f:
                data = json.load(f)
                self.instructions = data.get('instructions', [])
                self.config = data.get('config', {})
                self.setup = data.get('setup', {})
                print(f"✅ Loaded {len(self.instructions)} instructions from {self.json_file}")
        except Exception as e:
            print(f"❌ Error loading JSON file: {e}")
            sys.exit(1)
            
    def load_template(self) -> str:
        """Load the Rust template file"""
        try:
            with open(self.template_file, 'r') as f:
                return f.read()
        except Exception as e:
            print(f"❌ Error loading template file: {e}")
            sys.exit(1)
            
    def format_instruction(self, instr: dict) -> str:
        """Format a single instruction for inline assembly"""
        mnemonic = instr['mnemonic']
        args = instr.get('args', [])
        description = instr.get('description', '')
        
        # Format arguments
        if args:
            formatted_args = ', '.join(str(arg) for arg in args)
            asm_line = f"{mnemonic} {formatted_args}"
        else:
            asm_line = mnemonic
            
        # Add comment with description
        if description:
            return f'            "{asm_line}",  // {description}'
        else:
            return f'            "{asm_line}",'
    
    def generate_assembly_block(self) -> str:
        """Generate the complete inline assembly block"""
        max_instructions = self.config.get('max_instructions', 50)
        
        # Limit instructions if needed
        selected_instructions = self.instructions[:max_instructions]
        
        assembly_lines = []
        assembly_lines.append('        asm!(')
        
        # Add each instruction
        for i, instr in enumerate(selected_instructions):
            line = self.format_instruction(instr)
            # Remove comma from last instruction
            if i == len(selected_instructions) - 1:
                line = line.rstrip(',')
            assembly_lines.append(line)
            
        assembly_lines.append('        );')
        
        return '\n'.join(assembly_lines)
    
    def generate_program(self, output_file: str):
        """Generate the complete Rust program"""
        template = self.load_template()
        
        # Generate assembly block
        assembly_block = self.generate_assembly_block()
        
        # Replace placeholder in template
        generated_code = template.replace(
            '        // GENERATED_ASSEMBLY_PLACEHOLDER\n        asm!("nop"); // Default fallback',
            assembly_block
        )
        
        # Write generated program
        try:
            with open(output_file, 'w') as f:
                f.write(generated_code)
            print(f"✅ Generated Rust program: {output_file}")
        except Exception as e:
            print(f"❌ Error writing output file: {e}")
            sys.exit(1)
    
    def create_cargo_project(self, project_name: str):
        """Create a complete Cargo project for the generated program"""
        project_dir = Path(project_name)
        
        # Create directory structure
        project_dir.mkdir(exist_ok=True)
        src_dir = project_dir / "src"
        src_dir.mkdir(exist_ok=True)
        
        # Generate Cargo.toml
        cargo_toml = f"""[package]
name = "{project_name}"
version = "1.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
sp1-zkvm = {{ path = "../crates/zkvm/entrypoint" }}
"""
        
        with open(project_dir / "Cargo.toml", "w") as f:
            f.write(cargo_toml)
        
        # Generate main.rs
        main_rs_path = src_dir / "main.rs"
        self.generate_program(str(main_rs_path))
        
        print(f"✅ Created Cargo project: {project_dir}")
        return project_dir
    
    def create_test_script(self, project_name: str, project_dir: Path):
        """Create a test script to execute the generated program"""
        test_script_dir = project_dir / "test-script"
        test_script_dir.mkdir(exist_ok=True)
        
        # Create Cargo.toml for test script
        test_cargo_toml = f"""[package]
name = "test-script"
version = "1.0.0"
edition = "2021"

[workspace]

[dependencies]
sp1-sdk = {{ path = "../../crates/sdk" }}
tokio = {{ version = "1.0", features = ["full"] }}

[build-dependencies]
sp1-build = {{ path = "../../crates/build" }}
"""
        
        with open(test_script_dir / "Cargo.toml", "w") as f:
            f.write(test_cargo_toml)
        
        # Create build.rs
        build_rs = f"""fn main() {{
    sp1_build::build_program("../{project_name}");
}}"""
        
        with open(test_script_dir / "build.rs", "w") as f:
            f.write(build_rs)
        
        # Create src directory
        (test_script_dir / "src").mkdir(exist_ok=True)
        
        return test_script_dir
    
    def execute_program(self, project_name: str, project_dir: Path):
        """Execute the generated program in SP1 zkVM using the examples pattern"""
        print(f"🚀 Executing program: {project_name}")
        exec_start = time.time()
        
        # Create execution script following the Fibonacci example pattern
        execution_script = f"""use sp1_sdk::{{
    include_elf, utils, Elf, ProverClient, SP1Stdin, Prover,
}};

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("{project_name}");

#[tokio::main]
async fn main() {{
    // Setup logging.
    utils::setup_logger();

    println!("🧪 Testing assembly program: {project_name}");
    println!("📋 Instructions: {len(self.instructions)}");

    // Create an input stream (empty for our assembly test)
    let stdin = SP1Stdin::new();

    // Create a `ProverClient` method.
    let client = ProverClient::builder().cpu().build().await;

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
    println!("✅ Program executed successfully!");
    println!("📊 Executed program with {{}} cycles", report.total_instruction_count());
}}
"""
        
        # Create execution directory outside examples to avoid workspace conflicts
        exec_dir = Path(f"{project_name}-execution")
        exec_script_dir = exec_dir / "script"
        exec_script_dir.mkdir(parents=True, exist_ok=True)
        (exec_script_dir / "src").mkdir(exist_ok=True)
        
        # Copy the generated program to execution structure
        exec_program_dir = exec_dir / "program"
        if exec_program_dir.exists():
            shutil.rmtree(exec_program_dir)
        shutil.copytree(project_dir, exec_program_dir)
        
        # Fix the program's Cargo.toml to use correct paths
        program_cargo_path = exec_program_dir / "Cargo.toml"
        with open(program_cargo_path, 'r') as f:
            cargo_content = f.read()
        
        # Replace the path to use the correct relative path from execution directory
        cargo_content = cargo_content.replace(
            'sp1-zkvm = { path = "../crates/zkvm/entrypoint" }',
            'sp1-zkvm = { path = "../../crates/zkvm/entrypoint" }'
        )
        
        with open(program_cargo_path, 'w') as f:
            f.write(cargo_content)
        
        # Create script Cargo.toml (standalone, not in workspace)
        script_cargo = f"""[package]
name = "{project_name}-script"
version = "1.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
sp1-sdk = {{ path = "../../crates/sdk" }}
tokio = {{ version = "1.0", features = ["full"] }}

[build-dependencies]
sp1-build = {{ path = "../../crates/build" }}
"""
        
        with open(exec_script_dir / "Cargo.toml", "w") as f:
            f.write(script_cargo)
        
        # Create script main.rs
        with open(exec_script_dir / "src" / "main.rs", "w") as f:
            f.write(execution_script)
        
        # Create script build.rs
        script_build = f"""fn main() {{
    sp1_build::build_program("../program");
}}"""
        
        with open(exec_script_dir / "build.rs", "w") as f:
            f.write(script_build)
        
        # Execute the test
        original_dir = os.getcwd()
        try:
            os.chdir(exec_script_dir)
            
            print(f"🔨 Compiling execution script...")
            compile_start = time.time()
            compile_result = os.system("cargo build --release")
            compile_time = time.time() - compile_start
            if compile_result != 0:
                print(f"❌ Execution script compilation failed! (took {compile_time:.2f}s)")
                return False
            print(f"✅ Script compiled successfully! (took {compile_time:.2f}s)")
            
            print(f"🏃 Running execution...")
            run_start = time.time()
            run_result = os.system("cargo run --release")
            run_time = time.time() - run_start
            total_exec_time = time.time() - exec_start
            print(f"⏱️  Execution took {run_time:.2f}s (total exec time: {total_exec_time:.2f}s)")
            return run_result == 0
            
        except Exception as e:
            print(f"❌ Execution failed with exception: {{e}}")
            return False
        finally:
            os.chdir(original_dir)

def main():
    # Start timing
    start_time = time.time()
    
    parser = argparse.ArgumentParser(description="Generate SP1 assembly fuzzing programs from JSON")
    parser.add_argument("json_file", help="JSON file with instruction definitions")
    parser.add_argument("-t", "--template", default="asm-template.rs", 
                       help="Rust template file")
    parser.add_argument("-o", "--output", default="generated_program.rs",
                       help="Output Rust file")
    parser.add_argument("-p", "--project", help="Create complete Cargo project")
    parser.add_argument("--compile", action="store_true",
                       help="Compile to ELF after generation")
    parser.add_argument("--execute", action="store_true",
                       help="Execute the generated program in SP1 zkVM")
    
    args = parser.parse_args()
    
    # Check if files exist
    if not os.path.exists(args.json_file):
        print(f"❌ JSON file not found: {args.json_file}")
        sys.exit(1)
        
    if not os.path.exists(args.template):
        print(f"❌ Template file not found: {args.template}")
        sys.exit(1)
    
    # Create generator
    generator = SimpleAssemblyGenerator(args.json_file, args.template)
    generator.load_json()
    
    if args.project:
        print(f"⏱️  Starting project generation at {time.strftime('%H:%M:%S')}")
        # Create complete project
        project_dir = generator.create_cargo_project(args.project)
        
        if args.compile:
            # Compile the project
            compile_start = time.time()
            original_dir = os.getcwd()
            try:
                os.chdir(project_dir)
                compile_cmd = "cargo prove build"
                print(f"🔨 Compiling with: {compile_cmd}")
                result = os.system(compile_cmd)
                if result == 0:
                    compile_time = time.time() - compile_start
                    print(f"✅ Compilation successful! (took {compile_time:.2f}s)")
                    
                    # Look for generated ELF
                    import glob
                    elf_pattern = f"target/elf-compilation/*/release/{args.project}"
                    elf_files = glob.glob(elf_pattern)
                    if elf_files:
                        print(f"📁 ELF generated: {elf_files[0]}")
                    else:
                        print("⚠️  ELF not found at expected location")
                else:
                    print("❌ Compilation failed!")
                    return
            finally:
                os.chdir(original_dir)
        
        if args.execute:
            # Execute the program
            exec_start = time.time()
            success = generator.execute_program(args.project, project_dir)
            exec_time = time.time() - exec_start
            if success:
                print(f"🎉 Program execution completed successfully! (took {exec_time:.2f}s)")
            else:
                print(f"💥 Program execution failed! (took {exec_time:.2f}s)")
                sys.exit(1)
    else:
        # Generate single file
        generator.generate_program(args.output)
        
        if args.compile:
            print("Note: --compile requires --project flag")
        if args.execute:
            print("Note: --execute requires --project flag")
    
    # Calculate and display total time
    total_time = time.time() - start_time
    print(f"\n⏱️  TOTAL FUZZER TIME: {total_time:.2f} seconds ({total_time/60:.2f} minutes)")
    print(f"🏁 Fuzzer completed at {time.strftime('%H:%M:%S')}")
    
if __name__ == "__main__":
    main()
