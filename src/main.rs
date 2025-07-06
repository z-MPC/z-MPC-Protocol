//! z-MPC CLI Engine
//! 
//! Command-line interface for z-MPC operations:
//! - share --curve [k1|r1|ed25519]
//! - commit --value <b_{-1,i}>
//! - verify --commitment <C_i>
//! - combine → Σb_{-1,i} calculation
//! - network --start distributed protocol

use clap::{Parser, Subcommand};
use z_mpc::{
    init, Error, Result, CurveType, SharingParams, LaurentSeries, 
    PedersenCommitment, ZeroKnowledgeProof, laurent::Share,
    pedersen::utils as pedersen_utils, zkp::utils as zkp_utils,
    laurent::utils as laurent_utils, network::utils as network_utils,
    NetworkCoordinator
};
use std::str::FromStr;
use serde_json;

#[derive(Parser)]
#[command(name = "z-mpc")]
#[command(about = "Laurent Series based One-Round Secret Sharing with ZK-Proof")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate secret shares using Laurent series
    Share {
        /// Curve type (k1, r1, ed25519)
        #[arg(short, long, value_enum)]
        curve: CurveTypeArg,
        
        /// Threshold for secret sharing
        #[arg(short, long, default_value = "3")]
        threshold: usize,
        
        /// Number of participants
        #[arg(short, long, default_value = "5")]
        participants: usize,
        
        /// Output file for shares
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Create Pedersen commitment for a value
    Commit {
        /// Value to commit (hex string)
        #[arg(short, long)]
        value: String,
        
        /// Curve type
        #[arg(short, long, value_enum)]
        curve: CurveTypeArg,
        
        /// Output file for commitment
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Verify a Pedersen commitment
    Verify {
        /// Commitment to verify (hex string)
        #[arg(short, long)]
        commitment: String,
        
        /// Value that was committed (hex string)
        #[arg(short, long)]
        value: String,
        
        /// Randomness used (hex string)
        #[arg(short, long)]
        randomness: String,
        
        /// Curve type
        #[arg(short, long, value_enum)]
        curve: CurveTypeArg,
    },
    
    /// Combine shares to reconstruct secret
    Combine {
        /// Input file containing shares (JSON)
        #[arg(short, long)]
        input: String,
        
        /// Curve type
        #[arg(short, long, value_enum)]
        curve: CurveTypeArg,
        
        /// Output file for reconstructed secret
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Generate zero-knowledge proof for a commitment
    Prove {
        /// Share value (hex string)
        #[arg(short, long)]
        value: String,
        
        /// Randomness used (hex string)
        #[arg(short, long)]
        randomness: String,
        
        /// Curve type
        #[arg(short, long, value_enum)]
        curve: CurveTypeArg,
        
        /// Output file for proof
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Verify zero-knowledge proof
    VerifyProof {
        /// Proof file (JSON)
        #[arg(short, long)]
        proof: String,
        
        /// Curve type
        #[arg(short, long, value_enum)]
        curve: CurveTypeArg,
    },
    
    /// Sign a message using Schnorr signature
    Sign {
        /// Message to sign
        #[arg(short, long)]
        message: String,
        
        /// Private key (hex string)
        #[arg(short, long)]
        private_key: String,
        
        /// Curve type
        #[arg(short, long, value_enum)]
        curve: CurveTypeArg,
        
        /// Output file for signature
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Verify Schnorr signature
    VerifySignature {
        /// Signature file (JSON)
        #[arg(short, long)]
        signature: String,
        
        /// Message that was signed
        #[arg(short, long)]
        message: String,
    },
    
    /// Start distributed network protocol
    Network {
        /// Number of participants
        #[arg(short, long, default_value = "4")]
        participants: usize,
        
        /// Threshold for secret sharing
        #[arg(short, long, default_value = "3")]
        threshold: usize,
        
        /// Curve type
        #[arg(short, long, value_enum)]
        curve: CurveTypeArg,
        
        /// Port base for network nodes
        #[arg(short, long, default_value = "8000")]
        port_base: u16,
    },
    
    /// Run integration tests
    Test {
        /// Run specific test (all, flow, network, curves, errors, performance, security)
        #[arg(short, long, default_value = "all")]
        test: String,
        
        /// Enable verbose test output
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CurveTypeArg {
    K1,
    R1,
    Ed25519,
}

impl From<CurveTypeArg> for CurveType {
    fn from(arg: CurveTypeArg) -> Self {
        match arg {
            CurveTypeArg::K1 => CurveType::Secp256k1,
            CurveTypeArg::R1 => CurveType::P256,
            CurveTypeArg::Ed25519 => CurveType::Edwards25519,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize z-MPC library
    init()?;
    
    let cli = Cli::parse();
    
    if cli.verbose {
        tracing::info!("z-MPC CLI started with verbose logging");
    }
    
    match cli.command {
        Commands::Share { curve, threshold, participants, output } => {
            handle_share(curve.into(), threshold, participants, output)?;
        }
        Commands::Commit { value, curve, output } => {
            handle_commit(value, curve.into(), output)?;
        }
        Commands::Verify { commitment, value, randomness, curve } => {
            handle_verify(commitment, value, randomness, curve.into())?;
        }
        Commands::Combine { input, curve, output } => {
            handle_combine(input, curve.into(), output)?;
        }
        Commands::Prove { value, randomness, curve, output } => {
            handle_prove(value, randomness, curve.into(), output)?;
        }
        Commands::VerifyProof { proof, curve } => {
            handle_verify_proof(proof, curve.into())?;
        }
        Commands::Sign { message, private_key, curve, output } => {
            handle_sign(message, private_key, curve.into(), output)?;
        }
        Commands::VerifySignature { signature, message } => {
            handle_verify_signature(signature, message)?;
        }
        Commands::Network { participants, threshold, curve, port_base } => {
            handle_network(participants, threshold, curve.into(), port_base).await?;
        }
        Commands::Test { test, verbose } => {
            handle_test(test, verbose).await?;
        }
    }
    
    Ok(())
}

fn handle_share(curve_type: CurveType, threshold: usize, participants: usize, output: Option<String>) -> Result<()> {
    println!("Generating shares for curve: {}", curve_type);
    println!("Threshold: {}, Participants: {}", threshold, participants);
    
    // Validate parameters
    let params = SharingParams {
        curve_type,
        threshold,
        participants,
    };
    laurent_utils::validate_params(&params)?;
    
    // Create Laurent series
    let laurent = LaurentSeries::new(&params)?;
    
    // Generate shares
    let shares = laurent.generate_shares()?;
    
    println!("Generated {} shares:", shares.len());
    for share in &shares {
        println!("  Share {}: {}", share.id, hex::encode(&share.value));
    }
    
    // Create commitments for all shares
    let committed_shares = pedersen_utils::commit_all_shares(&shares, curve_type)?;
    
    println!("Created commitments for all shares");
    
    // Output to file or stdout
    let output_data = serde_json::json!({
        "curve_type": curve_type.to_string(),
        "threshold": threshold,
        "participants": participants,
        "shares": shares,
        "committed_shares": committed_shares,
    });
    
    if let Some(output_file) = output {
        std::fs::write(output_file, serde_json::to_string_pretty(&output_data)?)?;
        println!("Shares saved to {}", output_file);
    } else {
        println!("{}", serde_json::to_string_pretty(&output_data)?);
    }
    
    Ok(())
}

fn handle_commit(value: String, curve_type: CurveType, output: Option<String>) -> Result<()> {
    println!("Creating commitment for curve: {}", curve_type);
    
    // Parse value
    let value_bytes = hex::decode(&value)
        .map_err(|_| Error::InvalidInput("Invalid hex value".to_string()))?;
    
    let curve = z_mpc::curve::create_curve(curve_type);
    let value_scalar = curve.scalar_from_bytes(&value_bytes)?;
    
    // Create Pedersen commitment
    let pedersen = PedersenCommitment::new(curve_type)?;
    let randomness = pedersen.generate_randomness();
    let commitment = pedersen.commit(&value_scalar, &randomness)?;
    
    println!("Commitment: {}", hex::encode(&commitment));
    println!("Randomness: {}", hex::encode(&randomness));
    
    // Output to file or stdout
    let output_data = serde_json::json!({
        "curve_type": curve_type.to_string(),
        "value": value,
        "commitment": hex::encode(&commitment),
        "randomness": hex::encode(&randomness),
    });
    
    if let Some(output_file) = output {
        std::fs::write(output_file, serde_json::to_string_pretty(&output_data)?)?;
        println!("Commitment saved to {}", output_file);
    } else {
        println!("{}", serde_json::to_string_pretty(&output_data)?);
    }
    
    Ok(())
}

fn handle_verify(commitment: String, value: String, randomness: String, curve_type: CurveType) -> Result<()> {
    println!("Verifying commitment for curve: {}", curve_type);
    
    // Parse inputs
    let commitment_bytes = hex::decode(&commitment)
        .map_err(|_| Error::InvalidInput("Invalid hex commitment".to_string()))?;
    let value_bytes = hex::decode(&value)
        .map_err(|_| Error::InvalidInput("Invalid hex value".to_string()))?;
    let randomness_bytes = hex::decode(&randomness)
        .map_err(|_| Error::InvalidInput("Invalid hex randomness".to_string()))?;
    
    let curve = z_mpc::curve::create_curve(curve_type);
    let value_scalar = curve.scalar_from_bytes(&value_bytes)?;
    
    // Verify commitment
    let pedersen = PedersenCommitment::new(curve_type)?;
    let is_valid = pedersen.verify(&commitment_bytes, &value_scalar, &randomness_bytes)?;
    
    if is_valid {
        println!("✅ Commitment verification successful");
    } else {
        println!("❌ Commitment verification failed");
        return Err(Error::CommitmentError("Invalid commitment".to_string()));
    }
    
    Ok(())
}

fn handle_combine(input: String, curve_type: CurveType, output: Option<String>) -> Result<()> {
    println!("Combining shares for curve: {}", curve_type);
    
    // Read input file
    let input_data = std::fs::read_to_string(&input)?;
    let data: serde_json::Value = serde_json::from_str(&input_data)?;
    
    // Extract shares
    let shares_data = data["shares"].as_array()
        .ok_or_else(|| Error::InvalidInput("Invalid shares data".to_string()))?;
    
    let mut shares = Vec::new();
    for share_data in shares_data {
        let share: Share = serde_json::from_value(share_data.clone())?;
        shares.push(share);
    }
    
    println!("Loaded {} shares", shares.len());
    
    // Create Laurent series for reconstruction
    let threshold = shares.len();
    let params = SharingParams {
        curve_type,
        threshold,
        participants: threshold,
    };
    
    let laurent = LaurentSeries::new(&params)?;
    
    // Reconstruct secret
    let result = laurent.reconstruct_secret(&shares)?;
    
    println!("Secret reconstructed: {}", hex::encode(&result.secret));
    println!("Participants used: {:?}", result.participants_used);
    
    // Output to file or stdout
    let output_data = serde_json::json!({
        "curve_type": curve_type.to_string(),
        "secret": hex::encode(&result.secret),
        "valid": result.valid,
        "participants_used": result.participants_used,
    });
    
    if let Some(output_file) = output {
        std::fs::write(output_file, serde_json::to_string_pretty(&output_data)?)?;
        println!("Reconstruction result saved to {}", output_file);
    } else {
        println!("{}", serde_json::to_string_pretty(&output_data)?);
    }
    
    Ok(())
}

fn handle_prove(value: String, randomness: String, curve_type: CurveType, output: Option<String>) -> Result<()> {
    println!("Generating zero-knowledge proof for curve: {}", curve_type);
    
    // Parse inputs
    let value_bytes = hex::decode(&value)
        .map_err(|_| Error::InvalidInput("Invalid hex value".to_string()))?;
    let randomness_bytes = hex::decode(&randomness)
        .map_err(|_| Error::InvalidInput("Invalid hex randomness".to_string()))?;
    
    let curve = z_mpc::curve::create_curve(curve_type);
    let value_scalar = curve.scalar_from_bytes(&value_bytes)?;
    
    // Create share for proof
    let share = Share::new(1, value_bytes);
    
    // Create Pedersen commitment
    let pedersen = PedersenCommitment::new(curve_type)?;
    
    // Generate proof
    let proof = zkp_utils::prove_committed_share(&pedersen, &share, &randomness_bytes, curve_type)?;
    
    println!("Proof generated successfully");
    
    // Output to file or stdout
    let output_data = serde_json::json!({
        "curve_type": curve_type.to_string(),
        "proof": proof,
    });
    
    if let Some(output_file) = output {
        std::fs::write(output_file, serde_json::to_string_pretty(&output_data)?)?;
        println!("Proof saved to {}", output_file);
    } else {
        println!("{}", serde_json::to_string_pretty(&output_data)?);
    }
    
    Ok(())
}

fn handle_verify_proof(proof: String, curve_type: CurveType) -> Result<()> {
    println!("Verifying zero-knowledge proof for curve: {}", curve_type);
    
    // Read proof file
    let proof_data = std::fs::read_to_string(&proof)?;
    let proof: ZeroKnowledgeProof = serde_json::from_str(&proof_data)?;
    
    // Create Pedersen commitment for verification
    let pedersen = PedersenCommitment::new(curve_type)?;
    
    // Verify proof
    let is_valid = zkp_utils::verify_committed_share_proof(&proof, &pedersen)?;
    
    if is_valid {
        println!("✅ Zero-knowledge proof verification successful");
    } else {
        println!("❌ Zero-knowledge proof verification failed");
        return Err(Error::ZKProofError("Invalid proof".to_string()));
    }
    
    Ok(())
}

fn handle_sign(message: String, private_key: String, curve_type: CurveType, output: Option<String>) -> Result<()> {
    println!("Signing message for curve: {}", curve_type);
    
    // Parse private key
    let private_key_bytes = hex::decode(&private_key)
        .map_err(|_| Error::InvalidInput("Invalid hex private key".to_string()))?;
    
    let curve = z_mpc::curve::create_curve(curve_type);
    let private_key_scalar = curve.scalar_from_bytes(&private_key_bytes)?;
    
    // Sign message
    let signature = zkp_utils::sign_message(message.as_bytes(), &private_key_scalar, curve_type)?;
    
    println!("Message signed successfully");
    
    // Output to file or stdout
    let output_data = serde_json::json!({
        "curve_type": curve_type.to_string(),
        "message": message,
        "signature": signature,
    });
    
    if let Some(output_file) = output {
        std::fs::write(output_file, serde_json::to_string_pretty(&output_data)?)?;
        println!("Signature saved to {}", output_file);
    } else {
        println!("{}", serde_json::to_string_pretty(&output_data)?);
    }
    
    Ok(())
}

fn handle_verify_signature(signature: String, message: String) -> Result<()> {
    println!("Verifying Schnorr signature");
    
    // Read signature file
    let signature_data = std::fs::read_to_string(&signature)?;
    let data: serde_json::Value = serde_json::from_str(&signature_data)?;
    let signature: z_mpc::zkp::SchnorrSignature = serde_json::from_value(data["signature"].clone())?;
    
    // Verify signature
    let is_valid = zkp_utils::verify_signature(&signature, message.as_bytes())?;
    
    if is_valid {
        println!("✅ Schnorr signature verification successful");
    } else {
        println!("❌ Schnorr signature verification failed");
        return Err(Error::ZKProofError("Invalid signature".to_string()));
    }
    
    Ok(())
}

async fn handle_network(participants: usize, threshold: usize, curve_type: CurveType, port_base: u16) -> Result<()> {
    println!("🌐 Starting distributed network protocol");
    println!("Participants: {}, Threshold: {}, Curve: {}", participants, threshold, curve_type);
    println!("Port base: {}", port_base);
    
    // Create test network
    let mut coordinators = network_utils::create_test_network(participants, curve_type).await?;
    println!("✅ Network created with {} nodes", coordinators.len());
    
    // Run distributed protocol
    network_utils::run_distributed_protocol(&mut coordinators, threshold).await?;
    println!("✅ Distributed protocol completed successfully");
    
    // Show network status
    for (i, coordinator) in coordinators.iter().enumerate() {
        println!("   Node {}: {} - Protocol initialized", 
                 i + 1, 
                 coordinator.node.address);
    }
    
    println!("🎉 Network protocol execution completed");
    Ok(())
}

async fn handle_test(test: String, verbose: bool) -> Result<()> {
    println!("🧪 Running z-MPC tests");
    
    match test.as_str() {
        "all" => {
            println!("Running all tests...");
            run_all_tests(verbose).await?;
        }
        "flow" => {
            println!("Running complete flow test...");
            run_flow_test().await?;
        }
        "network" => {
            println!("Running network protocol test...");
            run_network_test().await?;
        }
        "curves" => {
            println!("Running multi-curve test...");
            run_curves_test().await?;
        }
        "errors" => {
            println!("Running error handling test...");
            run_errors_test().await?;
        }
        "performance" => {
            println!("Running performance test...");
            run_performance_test().await?;
        }
        "security" => {
            println!("Running security test...");
            run_security_test().await?;
        }
        _ => {
            return Err(Error::InvalidInput(format!("Unknown test: {}", test)));
        }
    }
    
    println!("🎉 All tests completed successfully");
    Ok(())
}

async fn run_all_tests(verbose: bool) -> Result<()> {
    run_flow_test().await?;
    run_network_test().await?;
    run_curves_test().await?;
    run_errors_test().await?;
    run_performance_test().await?;
    run_security_test().await?;
    Ok(())
}

async fn run_flow_test() -> Result<()> {
    // Initialize library
    init()?;
    
    // Test parameters
    let curve_type = CurveType::Secp256k1;
    let threshold = 3;
    let participants = 5;
    
    println!("🧪 Testing complete z-MPC flow with {} participants, threshold {}", participants, threshold);
    
    // 1. Create Laurent series
    let params = SharingParams {
        curve_type,
        threshold,
        participants,
    };
    
    let laurent = LaurentSeries::new(&params)?;
    println!("✅ Laurent series created");
    
    // 2. Generate shares
    let shares = laurent.generate_shares()?;
    assert_eq!(shares.len(), participants);
    println!("✅ Generated {} shares", shares.len());
    
    // 3. Create Pedersen commitments
    let committed_shares = pedersen_utils::commit_all_shares(&shares, curve_type)?;
    assert_eq!(committed_shares.len(), participants);
    println!("✅ Created {} commitments", committed_shares.len());
    
    // 4. Verify all commitments
    let all_valid = pedersen_utils::verify_all_committed_shares(&committed_shares, curve_type)?;
    assert!(all_valid);
    println!("✅ All commitments verified");
    
    // 5. Generate zero-knowledge proofs
    let pedersen = PedersenCommitment::new(curve_type)?;
    let mut proofs = Vec::new();
    
    for (share, committed_share) in shares.iter().zip(committed_shares.iter()) {
        let proof = zkp_utils::prove_committed_share(
            &pedersen,
            share,
            &committed_share.randomness,
            curve_type,
        )?;
        proofs.push(proof);
    }
    assert_eq!(proofs.len(), participants);
    println!("✅ Generated {} zero-knowledge proofs", proofs.len());
    
    // 6. Verify all proofs
    let all_proofs_valid = zkp_utils::batch_verify_proofs(&proofs, &pedersen)?;
    assert!(all_proofs_valid);
    println!("✅ All proofs verified");
    
    // 7. Reconstruct secret
    let result = laurent.reconstruct_secret(&shares)?;
    assert!(result.valid);
    assert_eq!(result.participants_used.len(), threshold);
    println!("✅ Secret reconstructed successfully");
    println!("   Secret: {}", hex::encode(&result.secret));
    println!("   Participants used: {:?}", result.participants_used);
    
    // 8. Verify reconstruction with different threshold
    let partial_shares = &shares[..threshold];
    let partial_result = laurent.reconstruct_secret(partial_shares)?;
    assert!(partial_result.valid);
    assert_eq!(partial_result.secret, result.secret);
    println!("✅ Partial reconstruction verified");
    
    println!("🎉 Complete z-MPC flow test passed!");
    Ok(())
}

async fn run_network_test() -> Result<()> {
    // Initialize library
    init()?;
    
    // Test parameters
    let curve_type = CurveType::Secp256k1;
    let num_participants = 4;
    let threshold = 3;
    
    println!("🌐 Testing distributed network protocol with {} participants", num_participants);
    
    // 1. Create test network
    let mut coordinators = network_utils::create_test_network(num_participants, curve_type).await?;
    assert_eq!(coordinators.len(), num_participants);
    println!("✅ Test network created with {} nodes", coordinators.len());
    
    // 2. Run distributed protocol
    network_utils::run_distributed_protocol(&mut coordinators, threshold).await?;
    println!("✅ Distributed protocol executed successfully");
    
    // 3. Verify all coordinators are initialized
    for (i, coordinator) in coordinators.iter().enumerate() {
        assert!(coordinator.laurent_series.is_some());
        assert!(coordinator.pedersen.is_some());
        println!("   Node {}: Protocol initialized", i + 1);
    }
    
    println!("🎉 Distributed network protocol test passed!");
    Ok(())
}

async fn run_curves_test() -> Result<()> {
    // Initialize library
    init()?;
    
    let curves = [CurveType::Secp256k1, CurveType::P256, CurveType::Edwards25519];
    let threshold = 3;
    let participants = 5;
    
    println!("🔧 Testing multi-curve support");
    
    for curve_type in curves.iter() {
        println!("   Testing curve: {}", curve_type);
        
        // 1. Create parameters
        let params = SharingParams {
            curve_type: *curve_type,
            threshold,
            participants,
        };
        
        // 2. Create Laurent series
        let laurent = LaurentSeries::new(&params)?;
        
        // 3. Generate shares
        let shares = laurent.generate_shares()?;
        assert_eq!(shares.len(), participants);
        
        // 4. Create commitments
        let committed_shares = pedersen_utils::commit_all_shares(&shares, *curve_type)?;
        assert_eq!(committed_shares.len(), participants);
        
        // 5. Verify commitments
        let all_valid = pedersen_utils::verify_all_committed_shares(&committed_shares, *curve_type)?;
        assert!(all_valid);
        
        // 6. Reconstruct secret
        let result = laurent.reconstruct_secret(&shares)?;
        assert!(result.valid);
        
        println!("     ✅ {} curve test passed", curve_type);
    }
    
    println!("🎉 Multi-curve support test passed!");
    Ok(())
}

async fn run_errors_test() -> Result<()> {
    // Initialize library
    init()?;
    
    println!("⚠️ Testing error handling");
    
    // 1. Test invalid threshold
    let params = SharingParams {
        curve_type: CurveType::Secp256k1,
        threshold: 1, // Invalid: threshold must be >= 2
        participants: 5,
    };
    
    let result = laurent_utils::validate_params(&params);
    assert!(result.is_err());
    println!("   ✅ Invalid threshold error handled");
    
    // 2. Test insufficient participants
    let params = SharingParams {
        curve_type: CurveType::Secp256k1,
        threshold: 5,
        participants: 3, // Invalid: participants must be >= threshold
    };
    
    let result = laurent_utils::validate_params(&params);
    assert!(result.is_err());
    println!("   ✅ Insufficient participants error handled");
    
    // 3. Test invalid curve type
    let result = "invalid_curve".parse::<CurveType>();
    assert!(result.is_err());
    println!("   ✅ Invalid curve type error handled");
    
    println!("🎉 Error handling test passed!");
    Ok(())
}

async fn run_performance_test() -> Result<()> {
    // Initialize library
    init()?;
    
    let curve_type = CurveType::Secp256k1;
    let threshold = 3;
    let participants = 10;
    
    println!("⚡ Performance benchmark test");
    
    let start = std::time::Instant::now();
    
    // 1. Create Laurent series
    let params = SharingParams {
        curve_type,
        threshold,
        participants,
    };
    let laurent = LaurentSeries::new(&params)?;
    
    // 2. Generate shares
    let shares = laurent.generate_shares()?;
    
    // 3. Create commitments
    let committed_shares = pedersen_utils::commit_all_shares(&shares, curve_type)?;
    
    // 4. Verify commitments
    let _all_valid = pedersen_utils::verify_all_committed_shares(&committed_shares, curve_type)?;
    
    // 5. Reconstruct secret
    let _result = laurent.reconstruct_secret(&shares)?;
    
    let duration = start.elapsed();
    println!("   ✅ Completed in {:?}", duration);
    println!("   📊 Performance: {} participants processed in {:?}", participants, duration);
    
    assert!(duration < std::time::Duration::from_secs(5)); // Should complete within 5 seconds
    println!("🎉 Performance benchmark test passed!");
    Ok(())
}

async fn run_security_test() -> Result<()> {
    // Initialize library
    init()?;
    
    println!("🔒 Testing security properties");
    
    let curve_type = CurveType::Secp256k1;
    let threshold = 3;
    let participants = 5;
    
    // 1. Test that insufficient shares cannot reconstruct secret
    let params = SharingParams {
        curve_type,
        threshold,
        participants,
    };
    let laurent = LaurentSeries::new(&params)?;
    let shares = laurent.generate_shares()?;
    
    // Try to reconstruct with insufficient shares
    let insufficient_shares = &shares[..threshold-1];
    let result = laurent.reconstruct_secret(insufficient_shares);
    assert!(result.is_err());
    println!("   ✅ Insufficient shares properly rejected");
    
    // 2. Test that different shares produce different results
    let params2 = SharingParams {
        curve_type,
        threshold,
        participants,
    };
    let laurent2 = LaurentSeries::new(&params2)?;
    let shares2 = laurent2.generate_shares()?;
    
    let result1 = laurent.reconstruct_secret(&shares)?;
    let result2 = laurent2.reconstruct_secret(&shares2)?;
    
    // Secrets should be different (high probability)
    assert_ne!(result1.secret, result2.secret);
    println!("   ✅ Different shares produce different secrets");
    
    // 3. Test commitment binding
    let pedersen = PedersenCommitment::new(curve_type)?;
    let value = laurent.get_secret_key()?;
    let randomness = pedersen.generate_randomness();
    let commitment = pedersen.commit(&value, &randomness)?;
    
    // Try to verify with wrong value
    let wrong_value = laurent2.get_secret_key()?;
    let is_valid = pedersen.verify(&commitment, &wrong_value, &randomness)?;
    assert!(!is_valid);
    println!("   ✅ Commitment binding property verified");
    
    println!("🎉 Security properties test passed!");
    Ok(())
} 