//! Integration tests for z-MPC
//! 
//! Tests the complete flow from share generation to secret reconstruction
//! including network communication and distributed protocol execution.

use z_mpc::{
    init, CurveType, SharingParams, LaurentSeries, 
    PedersenCommitment, ZeroKnowledgeProof, laurent::Share,
    pedersen::utils as pedersen_utils, zkp::utils as zkp_utils,
    laurent::utils as laurent_utils, network::utils as network_utils,
    NetworkCoordinator
};
use tokio;

#[tokio::test]
async fn test_complete_z_mpc_flow() {
    // Initialize library
    init().unwrap();
    
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
    
    let laurent = LaurentSeries::new(&params).unwrap();
    println!("✅ Laurent series created");
    
    // 2. Generate shares
    let shares = laurent.generate_shares().unwrap();
    assert_eq!(shares.len(), participants);
    println!("✅ Generated {} shares", shares.len());
    
    // 3. Create Pedersen commitments
    let committed_shares = pedersen_utils::commit_all_shares(&shares, curve_type).unwrap();
    assert_eq!(committed_shares.len(), participants);
    println!("✅ Created {} commitments", committed_shares.len());
    
    // 4. Verify all commitments
    let all_valid = pedersen_utils::verify_all_committed_shares(&committed_shares, curve_type).unwrap();
    assert!(all_valid);
    println!("✅ All commitments verified");
    
    // 5. Generate zero-knowledge proofs
    let pedersen = PedersenCommitment::new(curve_type).unwrap();
    let mut proofs = Vec::new();
    
    for (share, committed_share) in shares.iter().zip(committed_shares.iter()) {
        let proof = zkp_utils::prove_committed_share(
            &pedersen,
            share,
            &committed_share.randomness,
            curve_type,
        ).unwrap();
        proofs.push(proof);
    }
    assert_eq!(proofs.len(), participants);
    println!("✅ Generated {} zero-knowledge proofs", proofs.len());
    
    // 6. Verify all proofs
    let all_proofs_valid = zkp_utils::batch_verify_proofs(&proofs, &pedersen).unwrap();
    assert!(all_proofs_valid);
    println!("✅ All proofs verified");
    
    // 7. Reconstruct secret
    let result = laurent.reconstruct_secret(&shares).unwrap();
    assert!(result.valid);
    assert_eq!(result.participants_used.len(), threshold);
    println!("✅ Secret reconstructed successfully");
    println!("   Secret: {}", hex::encode(&result.secret));
    println!("   Participants used: {:?}", result.participants_used);
    
    // 8. Verify reconstruction with different threshold
    let partial_shares = &shares[..threshold];
    let partial_result = laurent.reconstruct_secret(partial_shares).unwrap();
    assert!(partial_result.valid);
    assert_eq!(partial_result.secret, result.secret);
    println!("✅ Partial reconstruction verified");
    
    println!("🎉 Complete z-MPC flow test passed!");
}

#[tokio::test]
async fn test_distributed_network_protocol() {
    // Initialize library
    init().unwrap();
    
    // Test parameters
    let curve_type = CurveType::Secp256k1;
    let num_participants = 4;
    let threshold = 3;
    
    println!("🌐 Testing distributed network protocol with {} participants", num_participants);
    
    // 1. Create test network
    let mut coordinators = network_utils::create_test_network(num_participants, curve_type).await.unwrap();
    assert_eq!(coordinators.len(), num_participants);
    println!("✅ Test network created with {} nodes", coordinators.len());
    
    // 2. Run distributed protocol
    network_utils::run_distributed_protocol(&mut coordinators, threshold).await.unwrap();
    println!("✅ Distributed protocol executed successfully");
    
    // 3. Verify all coordinators are initialized
    for (i, coordinator) in coordinators.iter().enumerate() {
        assert!(coordinator.laurent_series.is_some());
        assert!(coordinator.pedersen.is_some());
        println!("   Node {}: Protocol initialized", i + 1);
    }
    
    println!("🎉 Distributed network protocol test passed!");
}

#[tokio::test]
async fn test_multi_curve_support() {
    // Initialize library
    init().unwrap();
    
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
        let laurent = LaurentSeries::new(&params).unwrap();
        
        // 3. Generate shares
        let shares = laurent.generate_shares().unwrap();
        assert_eq!(shares.len(), participants);
        
        // 4. Create commitments
        let committed_shares = pedersen_utils::commit_all_shares(&shares, *curve_type).unwrap();
        assert_eq!(committed_shares.len(), participants);
        
        // 5. Verify commitments
        let all_valid = pedersen_utils::verify_all_committed_shares(&committed_shares, *curve_type).unwrap();
        assert!(all_valid);
        
        // 6. Reconstruct secret
        let result = laurent.reconstruct_secret(&shares).unwrap();
        assert!(result.valid);
        
        println!("     ✅ {} curve test passed", curve_type);
    }
    
    println!("🎉 Multi-curve support test passed!");
}

#[tokio::test]
async fn test_error_handling() {
    // Initialize library
    init().unwrap();
    
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
}

#[tokio::test]
async fn test_performance_benchmarks() {
    // Initialize library
    init().unwrap();
    
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
    let laurent = LaurentSeries::new(&params).unwrap();
    
    // 2. Generate shares
    let shares = laurent.generate_shares().unwrap();
    
    // 3. Create commitments
    let committed_shares = pedersen_utils::commit_all_shares(&shares, curve_type).unwrap();
    
    // 4. Verify commitments
    let _all_valid = pedersen_utils::verify_all_committed_shares(&committed_shares, curve_type).unwrap();
    
    // 5. Reconstruct secret
    let _result = laurent.reconstruct_secret(&shares).unwrap();
    
    let duration = start.elapsed();
    println!("   ✅ Completed in {:?}", duration);
    println!("   📊 Performance: {} participants processed in {:?}", participants, duration);
    
    assert!(duration < std::time::Duration::from_secs(5)); // Should complete within 5 seconds
    println!("🎉 Performance benchmark test passed!");
}

#[tokio::test]
async fn test_security_properties() {
    // Initialize library
    init().unwrap();
    
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
    let laurent = LaurentSeries::new(&params).unwrap();
    let shares = laurent.generate_shares().unwrap();
    
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
    let laurent2 = LaurentSeries::new(&params2).unwrap();
    let shares2 = laurent2.generate_shares().unwrap();
    
    let result1 = laurent.reconstruct_secret(&shares).unwrap();
    let result2 = laurent2.reconstruct_secret(&shares2).unwrap();
    
    // Secrets should be different (high probability)
    assert_ne!(result1.secret, result2.secret);
    println!("   ✅ Different shares produce different secrets");
    
    // 3. Test commitment binding
    let pedersen = PedersenCommitment::new(curve_type).unwrap();
    let value = laurent.get_secret_key().unwrap();
    let randomness = pedersen.generate_randomness();
    let commitment = pedersen.commit(&value, &randomness).unwrap();
    
    // Try to verify with wrong value
    let wrong_value = laurent2.get_secret_key().unwrap();
    let is_valid = pedersen.verify(&commitment, &wrong_value, &randomness).unwrap();
    assert!(!is_valid);
    println!("   ✅ Commitment binding property verified");
    
    println!("🎉 Security properties test passed!");
} 